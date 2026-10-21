"""
Corpus construction for the M1 URL model.

Sources (all public; check each licence before redistributing):
  train pool : UCI PhiUSIIL (CC BY 4.0)            https://archive.ics.uci.edu/dataset/967
               ealvaradob/phishing-dataset (Apache-2.0, HuggingFace)
  external   : pirocheto/phishing-url (CC BY 4.0, HuggingFace) - never trained on
  recent     : OpenPhish community feed + Phishing.Database "ACTIVE" links (MIT) - never trained on
  popular    : Tranco top sites (https://tranco-list.eu) - false-positive check only

Why this module exists: the corpora are biased in *opposite* directions (in PhiUSIIL no benign
URL has a path; in ealvaradob most benign URLs have one and the scheme is stripped). A model fed
the raw data learns the collection artefact, not phishing. `balance_shape` resamples the pool so
path/query presence is identical in both classes, and `normalise_url` removes scheme and "www.".
"""
from __future__ import annotations

import json
import random
import zipfile
from pathlib import Path
from typing import Callable, Dict, Iterable, List

import pandas as pd

from qrshield.netutil import normalise_url, registered_domain_of, safe_urlparse

RAW_URLS = {
    "phiusiil.zip": "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
    "ealv_urls.json": "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/urls.json",
    "piro_train.parquet": "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/main/data/train.parquet",
    "piro_test.parquet": "https://huggingface.co/datasets/pirocheto/phishing-url/resolve/main/data/test.parquet",
    "openphish.txt": "https://openphish.com/feed.txt",
    "phishingdb_active.txt": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "tranco.zip": "https://tranco-list.eu/top-1m.csv.zip",
}


def download_missing(raw_dir: Path, log: Callable[[str], None] = print) -> None:
    import requests
    raw_dir.mkdir(parents=True, exist_ok=True)
    for name, url in RAW_URLS.items():
        dest = raw_dir / name
        if dest.exists() and dest.stat().st_size > 0:
            continue
        log(f"downloading {name} ...")
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)


def _frame(urls: Iterable[str], labels: Iterable[int], source: str) -> pd.DataFrame:
    rows = []
    for u, y in zip(urls, labels):
        n = normalise_url(str(u))
        if n:
            rows.append((n, int(y), source))
    df = pd.DataFrame(rows, columns=["url", "label", "source"])
    df = df.drop_duplicates("url")
    df["group"] = df["url"].map(registered_domain_of)
    return df


# ---------------------------------------------------------------- loaders
def load_phiusiil(raw: Path) -> pd.DataFrame:
    with zipfile.ZipFile(raw / "phiusiil.zip") as z:
        name = next(n for n in z.namelist() if n.endswith(".csv"))
        with z.open(name) as f:
            df = pd.read_csv(f, usecols=["URL", "label"])
    return _frame(df["URL"], 1 - df["label"], "phiusiil")          # source: 1 = legitimate


def load_ealvaradob(raw: Path) -> pd.DataFrame:
    with open(raw / "ealv_urls.json", encoding="utf-8") as f:
        data = json.load(f)
    return _frame((r["text"] for r in data), (r["label"] for r in data), "ealvaradob")   # 1 = phishing


def load_pirocheto(raw: Path) -> pd.DataFrame:
    frames = []
    for name in ("piro_train.parquet", "piro_test.parquet"):
        df = pd.read_parquet(raw / name, columns=["url", "status"])
        frames.append(_frame(df["url"], (df["status"] == "phishing").astype(int), "pirocheto"))
    return pd.concat(frames, ignore_index=True).drop_duplicates("url")


def load_recent_phishing(raw: Path, sample: int = 20000, seed: int = 3) -> pd.DataFrame:
    urls: List[str] = []
    for line in (raw / "openphish.txt").read_text(encoding="utf-8", errors="ignore").splitlines():
        urls.append(line.strip())
    n_open = len(urls)
    pdb = [l.strip() for l in (raw / "phishingdb_active.txt").read_text(encoding="utf-8", errors="ignore").splitlines()
           if l.lower().startswith(("http://", "https://"))]
    random.Random(seed).shuffle(pdb)
    urls += pdb[:sample]
    df = _frame(urls, [1] * len(urls), "recent_feeds")
    df["feed"] = ["openphish" if i < n_open else "phishingdb" for i in range(len(df))][: len(df)]
    return df


def load_tranco(raw: Path, top: int = 20000) -> pd.DataFrame:
    with zipfile.ZipFile(raw / "tranco.zip") as z:
        with z.open(z.namelist()[0]) as f:
            df = pd.read_csv(f, header=None, names=["rank", "domain"], nrows=top)
    return _frame(df["domain"].map(lambda d: f"{d}/"), [0] * len(df), "tranco_top")


# ---------------------------------------------------------------- balancing
def shape_bucket(url: str) -> str:
    p = safe_urlparse("http://" + url)
    has_path = bool(p and len(p.path) > 1)
    has_query = bool(p and p.query)
    return f"{int(has_path)}{int(has_query)}"


def cap_per_domain(df: pd.DataFrame, cap: int, seed: int = 1) -> pd.DataFrame:
    """Limit URLs per (domain, class) so mass-hosting platforms cannot dominate."""
    shuffled = df.sample(frac=1.0, random_state=seed)
    return shuffled.groupby(["group", "label"], sort=False).head(cap)


def balance_shape(df: pd.DataFrame, n_per_class: int, seed: int = 2) -> pd.DataFrame:
    """Resample so each class has the SAME mix of (has_path, has_query) buckets.

    The target mix is the *smaller* of the two classes' availability in every bucket, scaled to
    n_per_class, so neither class can be told apart by path/query presence.
    """
    df = df.copy()
    df["bucket"] = df["url"].map(shape_bucket)
    counts = df.groupby(["label", "bucket"]).size().unstack(fill_value=0)
    avail = counts.min(axis=0)                                 # per bucket: what both classes can supply
    total = avail.sum()
    out = []
    for label in (0, 1):
        for bucket, n_avail in avail.items():
            want = min(int(round(n_per_class * n_avail / total)), int(counts.loc[label, bucket]))
            part = df[(df.label == label) & (df.bucket == bucket)]
            out.append(part.sample(n=want, random_state=seed))
    res = pd.concat(out, ignore_index=True)
    k = res.groupby("label").size().min()                      # exact class balance
    res = pd.concat([g.sample(n=k, random_state=seed) for _, g in res.groupby("label")], ignore_index=True)
    return res.drop(columns="bucket").sample(frac=1.0, random_state=seed).reset_index(drop=True)


def shape_report(df: pd.DataFrame) -> Dict[str, Dict[str, float]]:
    d = df.copy()
    d["has_path"] = d["url"].map(lambda u: shape_bucket(u)[0] == "1")
    d["has_query"] = d["url"].map(lambda u: shape_bucket(u)[1] == "1")
    d["len"] = d["url"].str.len()
    g = d.groupby("label")[["has_path", "has_query", "len"]].mean().round(3)
    return {("phishing" if k == 1 else "benign"): v for k, v in g.to_dict("index").items()}
