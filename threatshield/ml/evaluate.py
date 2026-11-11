"""
Reload artifacts and recompute test metrics to prove reproducibility.
Exits with code 1 if any metric deviates by more than 0.001.
"""
from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import StratifiedShuffleSplit

ARTIFACTS = Path(__file__).parent / "artifacts"
SEED = 42

SPAMASSASSIN_URLS = [
    ("https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2", "ham"),
    ("https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2", "spam"),
    ("https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2", "spam"),
]
UCI_SMS_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"


def _load_all() -> pd.DataFrame:
    """Re-download and reconstruct the same deduplicated dataset used in training."""
    rows = []
    for url, lbl in SPAMASSASSIN_URLS:
        print(f"  Fetching {url} ...")
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read()
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tf:
            for m in tf.getmembers():
                if m.isfile() and not m.name.endswith("cmds"):
                    f = tf.extractfile(m)
                    if f:
                        try:
                            rows.append((f.read().decode("utf-8", errors="replace")[:4000], lbl, "email"))
                        except Exception:
                            pass

    print("  Fetching UCI SMS ...")
    with urllib.request.urlopen(UCI_SMS_URL, timeout=60) as r:
        data = r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        with zf.open("SMSSpamCollection") as f:
            for line in f:
                parts = line.decode("utf-8", errors="replace").strip().split("\t", 1)
                if len(parts) == 2:
                    lbl = "spam" if parts[0].strip() == "spam" else "ham"
                    rows.append((parts[1], lbl, "sms"))

    df = pd.DataFrame(rows, columns=["text", "label", "channel"])
    df["_h"] = df["text"].apply(lambda t: hashlib.md5(t.encode()).hexdigest())
    df = df.drop_duplicates("_h").drop(columns="_h").reset_index(drop=True)
    df["y"] = (df["label"] == "spam").astype(int)
    return df


def main():
    """Reload model and verify test metrics match saved metrics.json."""
    if not (ARTIFACTS / "model.joblib").exists():
        print("ERROR: model.joblib not found. Run: python ml/train.py")
        sys.exit(1)

    saved = json.loads((ARTIFACTS / "metrics.json").read_text())
    expected = saved["test_metrics_overall"]

    print("[1/3] Reloading model ...")
    pipeline = joblib.load(ARTIFACTS / "model.joblib")

    print("[2/3] Reloading data ...")
    df = _load_all()

    strat_key = df["channel"] + "_" + df["label"]
    sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    _, temp_idx = next(sss1.split(df, strat_key))

    df_temp = df.iloc[temp_idx].reset_index(drop=True)
    strat_temp = strat_key.iloc[temp_idx].reset_index(drop=True)

    sss2 = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    _, test_idx = next(sss2.split(df_temp, strat_temp))
    df_test = df_temp.iloc[test_idx].reset_index(drop=True)

    X_test = df_test["text"].tolist()
    y_test = df_test["y"].tolist()

    print("[3/3] Recomputing metrics ...")
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    recomputed = {
        "accuracy":  round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall":    round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1":        round(f1_score(y_test, y_pred, zero_division=0), 4),
        "roc_auc":   round(roc_auc_score(y_test, y_prob), 4),
    }

    print("\nMetric comparison (saved vs recomputed):")
    print(f"  {'Metric':<12} {'Saved':>8} {'Recomputed':>12} {'Match':>8}")
    print("  " + "-" * 44)
    all_ok = True
    for k in ["accuracy", "precision", "recall", "f1", "roc_auc"]:
        sv = expected[k]
        rv = recomputed[k]
        ok = abs(sv - rv) <= 0.001
        if not ok:
            all_ok = False
        status = "PASS" if ok else "FAIL"
        print(f"  {k:<12} {sv:>8.4f} {rv:>12.4f} {status:>8}")

    if all_ok:
        print("\n[OK] Reproducibility confirmed -- all metrics match within 0.001.")
    else:
        print("\n[FAIL] Reproducibility check failed -- metrics do not match.")
        sys.exit(1)


if __name__ == "__main__":
    main()
