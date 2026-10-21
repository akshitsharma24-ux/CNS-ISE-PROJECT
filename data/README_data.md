# Data

Nothing large is committed. Raw corpora are downloaded on demand into `data/url/` (git-ignored); what ships in the repo is small and listed at the bottom.

## 1. Link model (M1)

| Role | Source | Licence / terms | Used for |
|---|---|---|---|
| train pool | [UCI PhiUSIIL Phishing URL dataset](https://archive.ics.uci.edu/dataset/967) | CC BY 4.0 | training (benign + phishing) |
| train pool | [ealvaradob/phishing-dataset](https://huggingface.co/datasets/ealvaradob/phishing-dataset) `urls.json` | Apache-2.0 | training |
| external test | [pirocheto/phishing-url](https://huggingface.co/datasets/pirocheto/phishing-url) | CC BY 4.0 | **never trained on** - external evaluation + benchmark |
| recent phishing | [OpenPhish community feed](https://openphish.com/feed.txt) | free community feed; check their terms for non-research use | never trained on - 2026 recall + benchmark |
| recent phishing | [Phishing.Database ACTIVE links](https://github.com/mitchellkrogza/Phishing.Database) | MIT | never trained on - 2026 recall |
| popular domains | [Tranco list](https://tranco-list.eu) | see their licence page; **not redistributed** | false-positive check only |
| synthetic | `qrshield/url_layer/synthetic.py` (seeded) | project code | training only; **excluded from every reported metric** |

Rebuild: `python -m qrshield data` (downloads about 150 MB, then builds `data/url/*.parquet` and `docs/results/url_corpus.json`), then `python -m qrshield train-url`.

### Why the corpora are resampled (the leakage trap)

Public corpora are biased in opposite directions: in PhiUSIIL **no benign URL has a path or query** (benign rows are bare `https://www.<domain>`), in ealvaradob most benign URLs do and the scheme is stripped. A model trained on the raw data learns "has a path = phishing" - and then flags nearly every real QR link (`https://pay.citypark.example/m/42`, menus, tickets). `docs/evaluation.md` section 1.1 shows the measured bias. Defences, in `qrshield/url_layer/dataset.py`:

* scheme and a leading `www.` are removed and are not features;
* the pool is resampled so the share of URLs with a path / query is **identical in both classes**;
* at most 15 URLs per registered domain and class (mass-hosting platforms cannot dominate);
* every domain that appears in an evaluation set is removed from the training pool.

Not done (and stated plainly): a strict time split. The feeds carry no first-seen dates, so "2026 feeds" is a recency proxy, not a temporal holdout.

### The retraining base corpus

`qrshield/models/url_base_corpus.csv.gz` (about 2 MB) is the class-balanced 100,000-URL training sample the shipped model was trained on, so `python -m qrshield retrain`/the Admin button work from a fresh clone without downloading anything. `data/benchmark/url_benchmark.csv` is the fixed benchmark the retraining gate compares models on (real URLs from the external corpus, 2026 feeds and popular domains).

## 2. Sticker model (M2)

The shipped model is trained on **simulated photographs** (`qrshield/cv_layer/simulate.py`): eight surfaces, printed labels, direct prints, framed cards, laminated prints, genuine stickers (hard negatives) and five tamper styles, with shadows, gloss, lighting, perspective, blur, sensor noise and JPEG. Ground truth follows the physics (tampered = a different code really sits under the sticker). Results on this data measure the algorithm, not real-world accuracy.

### Adding real photos (recommended before the final evaluation)

Follow `scripts/collect_cv_dataset.md`, put the photos and a `metadata.csv` in `data/cv_images/` (template: `metadata.template.csv`), then:

```
python -m qrshield train-cv --real data/cv_images
```

Real photos are weighted 3x in the final model, and the report adds a *real-photos-only* grouped cross-validation result (by session) so you can quote a real number. Never use a random split - it lets the model memorise a table grain or a phone.

## 3. What ships in the repository

`qrshield/models/` (trained model files + the base corpus), `data/benchmark/url_benchmark.csv`, `docs/results/*.json` (generated metrics), `qrshield/url_layer/data/blocklist_demo.txt` (documentation entries only). Private keys, the registry database and the admin token live in `.qrshield/` and are git-ignored.
