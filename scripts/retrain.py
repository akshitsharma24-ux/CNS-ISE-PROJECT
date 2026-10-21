"""
Human-gated retraining from the command line (F35).

    python -m scripts.retrain

Trains a candidate on the bundled base corpus + reports an admin approved, compares it with the active
model on the fixed benchmark and canary links, and promotes it only if it is not worse.
"""
import json

from qrshield import retrain
from qrshield.registry import Registry


def main() -> int:
    reg = Registry().ensure_ready()
    result = retrain.run(reg)
    gate = result["gate"]
    print(f"candidate {result['version']}: {'PROMOTED' if result['promoted'] else 'REJECTED'} "
          f"(+{result['approved_reports_used']} approved reports, {result['seconds']} s)")
    for name, ok in gate["checks"].items():
        print(f"  [{'pass' if ok else 'FAIL'}] {name}")
    print(json.dumps({k: {m: gate[k][m] for m in ('roc_auc', 'tpr_at_1pct_fpr', 'fpr', 'canaries_correct')} for k in ('active', 'candidate')}, indent=2))
    return 0 if result["promoted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
