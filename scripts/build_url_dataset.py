"""
Build the M1 URL corpus from public sources.

    python -m scripts.build_url_dataset --download            # fetch raw files into data/url/raw
    python -m scripts.build_url_dataset --raw-dir some/dir    # use already-downloaded files

Outputs (git-ignored): data/url/{train_pool,external,recent_phishing,popular_benign}.parquet
See qrshield/url_layer/dataset.py for why the corpus is resampled the way it is.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from qrshield import config
from qrshield.url_layer import dataset as D
from qrshield.url_layer.synthetic import all_synthetic


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--raw-dir", type=Path, default=config.DATA_DIR / "url" / "raw")
    ap.add_argument("--out-dir", type=Path, default=config.DATA_DIR / "url")
    ap.add_argument("--download", action="store_true", help="download missing raw files first")
    ap.add_argument("--per-class", type=int, default=60000, help="rows per class in the balanced training pool")
    ap.add_argument("--domain-cap", type=int, default=15, help="max URLs per (domain, class)")
    args = ap.parse_args()

    if args.download:
        D.download_missing(args.raw_dir)
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print("loading train-pool sources ...")
    pool = pd.concat([D.load_phiusiil(args.raw_dir), D.load_ealvaradob(args.raw_dir)], ignore_index=True)
    raw_n, raw_shape = len(pool), D.shape_report(pool)
    raw_per_source = {s: D.shape_report(g) for s, g in pool.groupby("source")}
    print(f"  raw pool: {len(pool):,} rows  shape before balancing: {json.dumps(raw_shape)}")

    external = D.load_pirocheto(args.raw_dir)
    recent = D.load_recent_phishing(args.raw_dir)
    popular = D.load_tranco(args.raw_dir)

    # nothing in the evaluation sets may share a registered domain with the training pool
    held_out_domains = set(external.group) | set(recent.group) | set(popular.group)
    pool = pool[~pool.group.isin(held_out_domains)]

    pool = D.cap_per_domain(pool, args.domain_cap)
    pool = D.balance_shape(pool, args.per_class)
    print(f"  balanced pool: {len(pool):,} rows  shape after balancing: {json.dumps(D.shape_report(pool))}")
    bias = {"raw_pool_rows": int(raw_n), "shape_before_balancing": raw_shape, "balanced_pool_rows": int(len(pool)),
            "shape_after_balancing": D.shape_report(pool), "per_source_shape_raw": raw_per_source}

    synth = pd.DataFrame(all_synthetic(), columns=["url", "label", "source"])
    synth["group"] = synth["url"].map(D.registered_domain_of)
    pool = pd.concat([pool, synth], ignore_index=True)

    bias.update({"train_pool_with_synthetic_rows": int(len(pool)), "synthetic_rows": int(len(synth)),
                 "external_rows": int(len(external)), "recent_phishing_rows": int(len(recent)), "popular_rows": int(len(popular)),
                 "heldout_domains_removed_from_pool": len(held_out_domains)})
    results = config.REPO_ROOT / "docs" / "results"
    results.mkdir(parents=True, exist_ok=True)
    (results / "url_corpus.json").write_text(json.dumps(bias, indent=2), encoding="utf-8")
    pool.to_parquet(args.out_dir / "train_pool.parquet")
    external.to_parquet(args.out_dir / "external.parquet")
    recent.to_parquet(args.out_dir / "recent_phishing.parquet")
    popular.to_parquet(args.out_dir / "popular_benign.parquet")
    print("wrote:", ", ".join(p.name for p in sorted(args.out_dir.glob("*.parquet"))))
    print(f"  train_pool={len(pool):,} external={len(external):,} recent_phishing={len(recent):,} popular_benign={len(popular):,}")


if __name__ == "__main__":
    main()
