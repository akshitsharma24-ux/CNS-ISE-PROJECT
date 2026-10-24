"""
Registry service: issuer lifecycle, signed CRLs, feedback queue, audit + telemetry (F26, F34).

One `Registry` instance owns a SQLite database and a keystore under a runtime home
directory, and keeps a `TrustStore` (the verifier's view of the world) in sync with them.
Tests create isolated instances; the web app uses a single shared one.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from qrshield import config
from qrshield.crypto_layer import (
    DEFAULT_STORE,
    TrustStore,
    create_issuer_certificate,
    create_signed_crl,
    export_public_key_b64,
    key_revocation_id,
    load_public_key_b64,
    sign_url_token,
    validate_certified_domain,
)
from qrshield.crypto_layer.transparency import (
    consistency_proof, inclusion_proof, leaf_hash, merkle_root, sign_tree_head,
)
from qrshield.registry.keystore import Keystore
from qrshield.registry.models import (
    AuditLog, Base, CRLRecord, IssuerRecord, KeyRevocation, ModelVersion, ScanLog, ScanReport,
)

ISSUER_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
REPORT_LABELS = ("phishing", "benign", "tampered")

DEMO_ISSUERS = (
    {"issuer_id": "citypark-01", "name": "Mumbai Smart City Parking", "domain": "pay.citypark.example"},
    {"issuer_id": "spit-admit", "name": "SPIT Admissions Authority", "domain": "spit.ac.in"},
)


class RegistryError(Exception):
    """Business-rule violation; `status` maps to an HTTP status code in the API layer."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


class Registry:
    def __init__(self, home: Optional[Path] = None, trust_store: Optional[TrustStore] = None):
        self.home = Path(home) if home else config.home_dir()
        self.home.mkdir(parents=True, exist_ok=True)
        self.store = trust_store if trust_store is not None else DEFAULT_STORE
        self.keystore = Keystore(self.home)

        self.db_path = self.home / "registry.db"
        self.engine = create_engine(
            f"sqlite:///{self.db_path}", connect_args={"check_same_thread": False}, future=True
        )

        @event.listens_for(self.engine, "connect")
        def _pragmas(dbapi_conn, _):  # WAL keeps readers unblocked while an admin writes
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()

        self._sessions = sessionmaker(bind=self.engine, expire_on_commit=False, future=True)
        self._root_priv = None
        self._ready = False

    # ------------------------------------------------------------------ plumbing
    def close(self) -> None:
        """Release the SQLite file (needed on Windows before the home directory can be deleted)."""
        self.engine.dispose()

    @contextmanager
    def session(self) -> Iterator[Session]:
        db = self._sessions()
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def ensure_ready(self, seed_demo: bool = True) -> "Registry":
        """Create schema + root key, pin the root, load certificates and the current CRL."""
        if self._ready:
            return self
        Base.metadata.create_all(self.engine)
        self._root_priv, root_pub = self.keystore.root_keypair()
        self.store.set_root(root_pub)
        self.store.resolver = self._resolve_certificate
        if seed_demo:
            self._seed_demo_issuers()
        with self.session() as db:
            for rec in db.scalars(select(IssuerRecord)):
                self.store.add_certificate(json.loads(rec.certificate_json))
            if db.scalar(select(func.count()).select_from(CRLRecord)) == 0:
                self._publish_crl(db)
        self._install_latest_crl()
        self._ready = True
        return self

    @property
    def root_public_key_b64(self) -> str:
        return export_public_key_b64(self.store.root_public_key)

    def _resolve_certificate(self, issuer_id: str) -> Optional[Dict[str, Any]]:
        with self.session() as db:
            rec = db.get(IssuerRecord, issuer_id)
            return json.loads(rec.certificate_json) if rec else None

    def audit(self, action: str, subject: str, detail: str = "", db: Optional[Session] = None) -> None:
        row = AuditLog(action=action, subject=subject[:128], detail=detail[:2000])
        if db is not None:
            db.add(row)
        else:
            with self.session() as s:
                s.add(row)

    # ------------------------------------------------------------------ issuers
    def register_issuer(
        self,
        issuer_id: str,
        name: str,
        domain: str,
        public_key_b64: Optional[str] = None,
        actor: str = "admin",
    ) -> Dict[str, Any]:
        """Register a business and return its root-signed certificate.

        Without `public_key_b64` the registry generates and *holds* the issuer key (demo
        custody so the Issuer Portal can print QR codes).
        """
        issuer_id = (issuer_id or "").strip().lower()
        if not ISSUER_ID_RE.match(issuer_id):
            raise RegistryError("issuer_id must be 2-63 chars of a-z, 0-9 and '-'")
        name = (name or "").strip()
        if not 2 <= len(name) <= 128:
            raise RegistryError("name must be 2-128 characters")
        try:
            domain = validate_certified_domain(domain)
        except ValueError as exc:
            raise RegistryError(str(exc)) from exc

        managed = public_key_b64 is None
        key_id = "key-1"
        with self.session() as db:
            if db.get(IssuerRecord, issuer_id):
                raise RegistryError(f"issuer '{issuer_id}' already exists", status=409)
            if managed:
                pub = self.keystore.new_issuer_key(issuer_id, key_id)
            else:
                try:
                    pub = load_public_key_b64(public_key_b64)
                except ValueError as exc:
                    raise RegistryError("public_key_b64 is not a valid Ed25519 public key") from exc
            cert = create_issuer_certificate(
                issuer_id, name, domain, pub, self._root_priv, key_id=key_id
            )
            db.add(IssuerRecord(
                issuer_id=issuer_id, name=name, domain=domain, key_id=key_id,
                public_key_b64=export_public_key_b64(pub),
                certificate_json=json.dumps(cert), managed_key=managed,
            ))
            self.audit("issuer.register", issuer_id, f"domain={domain} managed={managed} by={actor}", db)
        self.store.add_certificate(cert)
        return cert

    def _seed_demo_issuers(self) -> None:
        for spec in DEMO_ISSUERS:
            with self.session() as db:
                exists = db.get(IssuerRecord, spec["issuer_id"]) is not None
            if not exists:
                self.register_issuer(spec["issuer_id"], spec["name"], spec["domain"], actor="seed")

    def list_issuers(self) -> List[Dict[str, Any]]:
        with self.session() as db:
            rows = db.scalars(select(IssuerRecord).order_by(IssuerRecord.created_at)).all()
        return [self._issuer_dict(r) for r in rows]

    @staticmethod
    def _issuer_dict(r: IssuerRecord) -> Dict[str, Any]:
        cert = json.loads(r.certificate_json)
        return {
            "issuer_id": r.issuer_id, "name": r.name, "domain": r.domain, "key_id": r.key_id,
            "managed_key": r.managed_key, "is_revoked": r.is_revoked,
            "revocation_reason": r.revocation_reason, "revoked_at": r.revoked_at,
            "created_at": r.created_at, "cert_valid_to": cert.get("valid_to"),
        }

    def get_certificate(self, issuer_id: str) -> Optional[Dict[str, Any]]:
        return self._resolve_certificate(issuer_id)

    def _entries(self, db: Session) -> List[Dict[str, Any]]:
        entries = []
        for r in db.scalars(select(IssuerRecord).where(IssuerRecord.is_revoked.is_(True))):
            entries.append({"id": r.issuer_id, "revoked_at": r.revoked_at or int(time.time()),
                            "reason": r.revocation_reason or "revoked"})
        for k in db.scalars(select(KeyRevocation)):
            entries.append({"id": k.revocation_id, "revoked_at": k.revoked_at, "reason": k.reason})
        return entries

    def _publish_crl(self, db: Session) -> Dict[str, Any]:
        last = db.scalar(select(func.max(CRLRecord.version))) or 0
        crl = create_signed_crl(self._entries(db), self._root_priv, version=last + 1)
        db.add(CRLRecord(version=crl["version"], issued_at=crl["issued_at"], crl_json=json.dumps(crl)))
        return crl

    def _install_latest_crl(self) -> Dict[str, Any]:
        crl = self.current_crl()
        ok, msg = self.store.install_crl(crl)
        if not ok and "rollback" not in msg:
            raise RuntimeError(f"registry produced an unverifiable CRL: {msg}")
        return crl

    def current_crl(self) -> Dict[str, Any]:
        with self.session() as db:
            rec = db.scalar(select(CRLRecord).order_by(CRLRecord.version.desc()).limit(1))
            if rec is None:
                crl = self._publish_crl(db)
                return crl
            return json.loads(rec.crl_json)

    def revoke_issuer(self, issuer_id: str, reason: str = "key compromised", actor: str = "admin") -> Dict[str, Any]:
        reason = (reason or "revoked").strip()[:200]
        with self.session() as db:
            rec = db.get(IssuerRecord, issuer_id)
            if rec is None:
                raise RegistryError(f"issuer '{issuer_id}' not found", status=404)
            if rec.is_revoked:
                raise RegistryError(f"issuer '{issuer_id}' is already revoked", status=409)
            rec.is_revoked, rec.revocation_reason, rec.revoked_at = True, reason, int(time.time())
            self.audit("issuer.revoke", issuer_id, f"reason={reason} by={actor}", db)
            db.flush()
            crl = self._publish_crl(db)
        self.store.install_crl(crl)
        return crl

    def restore_issuer(self, issuer_id: str, actor: str = "admin") -> Dict[str, Any]:
        """Un-revoke an issuer (e.g. revoked by mistake / demo reset); publishes a newer CRL."""
        with self.session() as db:
            rec = db.get(IssuerRecord, issuer_id)
            if rec is None:
                raise RegistryError(f"issuer '{issuer_id}' not found", status=404)
            if not rec.is_revoked:
                raise RegistryError(f"issuer '{issuer_id}' is not revoked", status=409)
            rec.is_revoked, rec.revocation_reason, rec.revoked_at = False, None, None
            self.audit("issuer.restore", issuer_id, f"by={actor}", db)
            db.flush()
            crl = self._publish_crl(db)
        self.store.install_crl(crl)
        return crl

    def rotate_issuer_key(self, issuer_id: str, actor: str = "admin") -> Dict[str, Any]:
        """Replace a managed issuer key: new certificate, old key id goes on the CRL."""
        with self.session() as db:
            rec = db.get(IssuerRecord, issuer_id)
            if rec is None:
                raise RegistryError(f"issuer '{issuer_id}' not found", status=404)
            if not rec.managed_key:
                raise RegistryError("only registry-managed issuer keys can be rotated here", status=409)
            old_kid = rec.key_id
            new_kid = f"key-{int(old_kid.split('-')[-1]) + 1}"
            pub = self.keystore.new_issuer_key(issuer_id, new_kid)
            cert = create_issuer_certificate(rec.issuer_id, rec.name, rec.domain, pub, self._root_priv, key_id=new_kid)
            rec.key_id, rec.public_key_b64, rec.certificate_json = new_kid, export_public_key_b64(pub), json.dumps(cert)
            db.add(KeyRevocation(revocation_id=key_revocation_id(issuer_id, old_kid),
                                 revoked_at=int(time.time()), reason="key rotated"))
            self.audit("issuer.rotate", issuer_id, f"{old_kid}->{new_kid} by={actor}", db)
            db.flush()
            crl = self._publish_crl(db)
        self.store.add_certificate(cert)
        self.store.install_crl(crl)
        return {"certificate": cert, "crl_version": crl["version"]}

    def sign_for_issuer(
        self, issuer_id: str, url: str, location_id: str = "counter-01", validity_hours: int = 48,
        allow_revoked: bool = False,
    ) -> Dict[str, Any]:
        """Sign a URL on behalf of a registry-managed issuer (Issuer Portal backend).

        `allow_revoked` exists only for demo scenarios that re-create a code printed *before* a
        revocation (so the audience can scan it and watch it come back REVOKED).
        """
        with self.session() as db:
            rec = db.get(IssuerRecord, issuer_id)
            if rec is None:
                raise RegistryError(f"issuer '{issuer_id}' not found", status=404)
            if rec.is_revoked and not allow_revoked:
                raise RegistryError(f"issuer '{issuer_id}' is revoked and cannot sign", status=409)
            if not rec.managed_key:
                raise RegistryError("this issuer holds its own private key; sign locally with scripts/make_signed_qr.py", status=409)
            key_id = rec.key_id
        priv = self.keystore.issuer_private_key(issuer_id, key_id)
        if priv is None:
            raise RegistryError("issuer key material is missing from the keystore", status=500)
        if not 0 <= validity_hours <= 24 * 365 * 5:
            raise RegistryError("validity_hours must be between 0 (never expires) and 43800")
        loc = (location_id or "counter-01").strip()[:48] or "counter-01"
        now = int(time.time())
        exp = 0 if validity_hours == 0 else now + validity_hours * 3600
        try:
            signed_url, token = sign_url_token(url, priv, issuer_id, key_id, loc, iat=now, exp=exp)
        except ValueError as exc:
            raise RegistryError(str(exc)) from exc
        self.audit("qr.sign", issuer_id, f"loc={loc} valid_h={validity_hours}")
        return {"signed_url": signed_url, "token": token}

    def reset_demo(self, actor: str = "admin") -> None:
        """Restore every revoked issuer so a demo can be repeated."""
        for item in self.list_issuers():
            if item["is_revoked"]:
                self.restore_issuer(item["issuer_id"], actor=actor)

    # ------------------------------------------------------------------ feedback
    def add_report(self, payload: str, user_label: str, note: str = "", verdict: Optional[str] = None) -> str:
        if user_label not in REPORT_LABELS:
            raise RegistryError(f"user_label must be one of {REPORT_LABELS}")
        payload = (payload or "").strip()
        if not payload or len(payload) > config.MAX_PAYLOAD_CHARS:
            raise RegistryError("payload is empty or too long")
        report_id = str(uuid.uuid4())
        with self.session() as db:
            db.add(ScanReport(
                report_id=report_id, payload_hash=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                url=payload, user_label=user_label, note=(note or "")[: config.MAX_NOTE_CHARS],
                verdict_at_report=verdict,
            ))
        return report_id

    def list_reports(self, status: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self.session() as db:
            q = select(ScanReport).order_by(ScanReport.created_at.desc()).limit(limit)
            if status:
                q = q.where(ScanReport.status == status)
            rows = db.scalars(q).all()
        return [{
            "report_id": r.report_id, "url": r.url, "payload_hash": r.payload_hash,
            "user_label": r.user_label, "note": r.note, "status": r.status,
            "verdict_at_report": r.verdict_at_report, "created_at": r.created_at,
            "reviewed_at": r.reviewed_at, "used_in_model": r.used_in_model,
        } for r in rows]

    def review_report(self, report_id: str, action: str, actor: str = "admin") -> str:
        if action not in ("approve", "reject"):
            raise RegistryError("action must be 'approve' or 'reject'")
        with self.session() as db:
            rec = db.get(ScanReport, report_id)
            if rec is None:
                raise RegistryError("report not found", status=404)
            rec.status = "approved" if action == "approve" else "rejected"
            rec.reviewed_at = int(time.time())
            self.audit("report.review", report_id, f"{rec.status} by={actor}", db)
            return rec.status

    def approved_reports(self, only_unused: bool = False) -> List[Dict[str, Any]]:
        with self.session() as db:
            q = select(ScanReport).where(ScanReport.status == "approved")
            if only_unused:
                q = q.where(ScanReport.used_in_model.is_(None))
            rows = db.scalars(q).all()
        return [{"report_id": r.report_id, "url": r.url, "user_label": r.user_label} for r in rows]

    def mark_reports_used(self, report_ids: List[str], version: str) -> None:
        with self.session() as db:
            for rid in report_ids:
                rec = db.get(ScanReport, rid)
                if rec:
                    rec.used_in_model = version

    # ------------------------------------------------------------------ telemetry
    def log_scan(self, **fields: Any) -> None:
        with self.session() as db:
            db.add(ScanLog(**fields))

    def stats(self) -> Dict[str, Any]:
        with self.session() as db:
            total = db.scalar(select(func.count()).select_from(ScanLog)) or 0
            by_verdict = dict(db.execute(select(ScanLog.verdict, func.count()).group_by(ScanLog.verdict)).all())
            latencies = sorted(db.scalars(select(ScanLog.elapsed_ms).order_by(ScanLog.created_at.desc()).limit(500)).all())
            pending = db.scalar(select(func.count()).select_from(ScanReport).where(ScanReport.status == "pending")) or 0
        def pct(p: float) -> Optional[float]:
            return round(latencies[min(len(latencies) - 1, int(p * len(latencies)))], 1) if latencies else None
        return {"scans_total": total, "by_verdict": by_verdict, "reports_pending": pending,
                "latency_ms_p50": pct(0.50), "latency_ms_p95": pct(0.95)}

    def recent_url_scores(self, limit: int = 1000) -> List[float]:
        """Link-risk scores of the most recent scans of web links (anonymous telemetry; used for drift monitoring)."""
        with self.session() as db:
            return [float(x) for x in db.scalars(select(ScanLog.url_risk).where(ScanLog.payload_type == "url")
                                                 .order_by(ScanLog.created_at.desc()).limit(limit)).all()]

    # ------------------------------------------------------------------ transparency log
    LOG_ACTIONS = ("issuer.register", "issuer.revoke", "issuer.restore", "issuer.rotate")

    def _log_entries(self) -> List[Dict[str, Any]]:
        """Certificate-lifecycle events in the order they happened; each is one leaf of the Merkle tree."""
        with self.session() as db:
            rows = db.scalars(select(AuditLog).where(AuditLog.action.in_(self.LOG_ACTIONS)).order_by(AuditLog.id)).all()
        return [{"index": i, "time": r.created_at, "action": r.action, "subject": r.subject, "detail": r.detail or ""}
                for i, r in enumerate(rows)]

    @staticmethod
    def log_leaf_data(entry: Dict[str, Any]) -> bytes:
        """Canonical bytes of one entry. The browser rebuilds exactly this string to re-check inclusion."""
        body = {"action": entry["action"], "detail": entry["detail"], "subject": entry["subject"], "time": entry["time"]}
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _log_hashes(self, entries: List[Dict[str, Any]]) -> List[bytes]:
        return [leaf_hash(self.log_leaf_data(e)) for e in entries]

    def log_snapshot(self) -> Dict[str, Any]:
        entries = self._log_entries()
        hashes = self._log_hashes(entries)
        root = merkle_root(hashes)
        head = sign_tree_head(len(entries), root, int(time.time()), self._root_priv)
        return {"head": head, "root_public_key": self.root_public_key_b64,
                "entries": [{**e, "leaf_hash": h.hex()} for e, h in zip(entries, hashes)]}

    def log_inclusion(self, index: int) -> Dict[str, Any]:
        entries = self._log_entries()
        if not 0 <= index < len(entries):
            raise RegistryError("no such log entry", status=404)
        hashes = self._log_hashes(entries)
        root = merkle_root(hashes)
        return {"entry": entries[index], "leaf_hash": hashes[index].hex(), "index": index, "size": len(entries),
                "root_hash": root.hex(), "path": [h.hex() for h in inclusion_proof(index, hashes)],
                "head": sign_tree_head(len(entries), root, int(time.time()), self._root_priv)}

    def log_consistency(self, first: int) -> Dict[str, Any]:
        """Proof that the log as it was at size `first` is a prefix of the log today."""
        entries = self._log_entries()
        if not 0 < first <= len(entries):
            raise RegistryError("first must be between 1 and the current log size", status=400)
        hashes = self._log_hashes(entries)
        return {"first": first, "second": len(entries), "first_root": merkle_root(hashes[:first]).hex(),
                "second_root": merkle_root(hashes).hex(), "path": [h.hex() for h in consistency_proof(first, hashes)]}

    def audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.session() as db:
            rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all()
        return [{"id": r.id, "created_at": r.created_at, "action": r.action,
                 "subject": r.subject, "detail": r.detail} for r in rows]

    # ------------------------------------------------------------------ models
    def record_model_version(self, kind: str, version: str, status: str, metrics: Dict[str, Any], note: str = "") -> None:
        with self.session() as db:
            db.add(ModelVersion(kind=kind, version=version, status=status,
                                metrics_json=json.dumps(metrics), note=note[:1000]))

    def list_model_versions(self, kind: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.session() as db:
            q = select(ModelVersion).order_by(ModelVersion.id.desc())
            if kind:
                q = q.where(ModelVersion.kind == kind)
            rows = db.scalars(q).all()
        return [{"kind": r.kind, "version": r.version, "status": r.status, "created_at": r.created_at,
                 "metrics": json.loads(r.metrics_json), "note": r.note} for r in rows]

    # ------------------------------------------------------------------ admin token
    def admin_token(self) -> str:
        """Token guarding privileged API routes. QRSHIELD_ADMIN_TOKEN overrides the file."""
        import os
        env = os.environ.get("QRSHIELD_ADMIN_TOKEN")
        if env:
            return env
        path = self.home / "admin_token"
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        token = secrets.token_urlsafe(24)
        path.write_text(token, encoding="utf-8")
        try:
            import os as _os
            _os.chmod(path, 0o600)
        except OSError:
            pass
        return token
