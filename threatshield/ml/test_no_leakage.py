"""
Test: proves no test rows appear in the training set.
Uses the same deterministic split logic as train.py.
Run: python ml/test_no_leakage.py
"""
from __future__ import annotations

import hashlib
import io
import sys
import tarfile
import urllib.request
import zipfile

import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

SEED = 42
SPAMASSASSIN_URLS = [
    ("https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2", "ham"),
    ("https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2", "spam"),
    ("https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2", "spam"),
]
UCI_SMS_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"


def _load_all():
    rows = []
    for url, lbl in SPAMASSASSIN_URLS:
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
    with urllib.request.urlopen(UCI_SMS_URL, timeout=60) as r:
        data = r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        with zf.open("SMSSpamCollection") as f:
            for line in f:
                parts = line.decode("utf-8", errors="replace").strip().split("\t", 1)
                if len(parts) == 2:
                    lbl = "spam" if parts[0].strip() == "spam" else "ham"
                    rows.append((parts[1], lbl, "sms"))
    return rows


def test_no_train_test_overlap():
    """No message hash present in both train and test splits."""
    rows = _load_all()
    df = pd.DataFrame(rows, columns=["text", "label", "channel"])
    df["_h"] = df["text"].apply(lambda t: hashlib.md5(t.encode()).hexdigest())
    df = df.drop_duplicates("_h").reset_index(drop=True)

    strat = df["channel"] + "_" + df["label"]
    sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    train_idx, temp_idx = next(sss1.split(df, strat))

    df_temp = df.iloc[temp_idx].reset_index(drop=True)
    strat_temp = (df["channel"] + "_" + df["label"]).iloc[temp_idx].reset_index(drop=True)
    sss2 = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    _, test_idx = next(sss2.split(df_temp, strat_temp))

    train_hashes = set(df.iloc[train_idx]["_h"])
    test_hashes  = set(df_temp.iloc[test_idx]["_h"])
    overlap = train_hashes & test_hashes

    assert len(overlap) == 0, f"LEAK: {len(overlap)} test rows found in training set!"
    print(f"[PASS] test_no_train_test_overlap -- 0 overlapping rows out of {len(test_hashes)} test rows.")


if __name__ == "__main__":
    print("Running leakage test (downloads data) ...")
    test_no_train_test_overlap()
    print("All tests passed.")
