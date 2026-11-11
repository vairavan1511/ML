"""
ThreatShield ML Training Pipeline
----------------------------------
Downloads SpamAssassin + UCI SMS, adds India smishing supplement,
trains 4 models, saves best by val-F1 to artifacts/.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import random
import tarfile
import time
import urllib.request
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC

from features import build_full_pipeline

SEED = 42
ARTIFACTS = Path(__file__).parent / "artifacts"
ARTIFACTS.mkdir(exist_ok=True)

SPAMASSASSIN_URLS = [
    ("https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2", "ham"),
    ("https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2", "spam"),
    ("https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2", "spam"),
]
UCI_SMS_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip"


def _india_smishing(n: int = 300) -> list[tuple[str, str]]:
    """Generate >=300 synthetic India-context smishing messages (training only)."""
    rng = random.Random(SEED)
    templates = [
        "Dear customer, your {bank} OTP is {otp}. Share it with our agent to unblock your account. Call {phone}.",
        "ALERT: Your {bank} account OTP {otp} expires in 5 mins. Confirm via {url} or call {phone}.",
        "Your {bank} account will be SUSPENDED. Complete KYC immediately at {url} or call {phone}.",
        "KYC update required for {bank}. Failure to update within 24 hrs will block your account. Visit {url}.",
        "You have a pending UPI collect request of Rs.{amount} from {bank}. Approve: {url}",
        "UPI ALERT: Rs.{amount} collect request pending. Approve now to avoid penalty: {url}",
        "Your {bank} account is BLOCKED due to suspicious activity. Call {phone} immediately to restore.",
        "URGENT: {bank} has blocked your debit card. Verify details at {url} within 2 hours.",
        "Your parcel is held at customs. Pay Rs.{amount} clearance fee at {url} to release. Ref#{ref}",
        "Delivery failed. Pay Rs.{amount} redelivery charge: {url}. Parcel returned in 24hrs.",
        "Congratulations! You won Rs.{prize} in {bank} Lucky Draw. Claim at {url} before {date}.",
        "WINNER! Your mobile number selected for Rs.{prize} prize. Send Aadhaar to {phone} to claim.",
        "NOTICE: Your electricity connection will be disconnected tonight due to unpaid bill. Pay now: {url}",
        "Last warning: Electricity bill overdue. Pay Rs.{amount} immediately at {url} or supply cut at {time}.",
        "Hiring! Work from home. Earn Rs.{salary}/day. No experience needed. WhatsApp {phone} now.",
        "Job offer: Data entry, Rs.{salary}/month. Apply: {url}. Limited seats. Register today.",
        "Pre-approved personal loan Rs.{loan} at 0% interest. No documents. Apply: {url}",
        "Instant loan Rs.{loan} credited in 10 mins. Download app: {url}. Offer expires today.",
    ]
    banks = ["SBI", "HDFC", "ICICI", "Axis", "PNB", "Kotak", "BOB"]
    domains = ["sbi-kyc.in", "hdfc-update.net", "icici-verify.co", "upi-collect.xyz",
               "paytm-offer.in", "nsdl-kyc.net", "aadhaar-link.org"]

    def rand_url():
        return f"http://{rng.choice(domains)}/{rng.randint(1000,9999)}"

    rows = []
    while len(rows) < n:
        tmpl = rng.choice(templates)
        msg = tmpl.format(
            bank=rng.choice(banks),
            otp=rng.randint(100000, 999999),
            phone=f"+91{rng.randint(7000000000,9999999999)}",
            url=rand_url(),
            amount=rng.choice([49, 99, 149, 199, 299, 499]),
            prize=f"{rng.randint(1,50)*10000:,}",
            ref=rng.randint(10000, 99999),
            date=f"{rng.randint(1,28)}/{rng.randint(1,12)}/2024",
            salary=rng.choice([500, 800, 1200, 1500, 2000]),
            loan=f"{rng.choice([50000,100000,200000,500000]):,}",
            time=f"{rng.randint(6,11)}PM",
        )
        rows.append((msg, "spam"))
    return rows


def _fetch(url: str, label: str) -> list[tuple[str, str]]:
    """Download and parse SpamAssassin tar.bz2 -> list of (text, label)."""
    print(f"  Downloading {url} ...")
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read()
    rows = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:bz2") as tf:
        for member in tf.getmembers():
            if member.isfile() and not member.name.endswith("cmds"):
                f = tf.extractfile(member)
                if f:
                    try:
                        text = f.read().decode("utf-8", errors="replace")
                        rows.append((text[:4000], label))
                    except Exception:
                        pass
    print(f"    -> {len(rows)} messages ({label})")
    return rows


def _fetch_uci_sms() -> list[tuple[str, str]]:
    """Download UCI SMS Spam Collection -> list of (text, label)."""
    print("  Downloading UCI SMS ...")
    with urllib.request.urlopen(UCI_SMS_URL, timeout=60) as r:
        data = r.read()
    rows = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        with zf.open("SMSSpamCollection") as f:
            for line in f:
                parts = line.decode("utf-8", errors="replace").strip().split("\t", 1)
                if len(parts) == 2:
                    label = "spam" if parts[0].strip() == "spam" else "ham"
                    rows.append((parts[1], label))
    print(f"    -> {len(rows)} SMS messages")
    return rows


def _metrics(name: str, y_true, y_pred, y_prob, channel: str | None = None) -> dict:
    """Compute classification metrics dict."""
    return {
        "model": name,
        "channel": channel or "overall",
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_true, y_prob), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def main(bert: bool = False):
    """Run full training pipeline."""
    # 1. Load data
    print("\n[1/6] Loading datasets ...")
    email_rows: list[tuple[str, str, str]] = []
    for url, lbl in SPAMASSASSIN_URLS:
        for text, l in _fetch(url, lbl):
            email_rows.append((text, l, "email"))

    sms_rows: list[tuple[str, str, str]] = []
    for text, lbl in _fetch_uci_sms():
        sms_rows.append((text, lbl, "sms"))

    india_rows: list[tuple[str, str, str]] = []
    for text, lbl in _india_smishing(300):
        india_rows.append((text, lbl, "sms_india_synthetic"))

    df_all = pd.DataFrame(email_rows + sms_rows, columns=["text", "label", "channel"])
    df_india = pd.DataFrame(india_rows, columns=["text", "label", "channel"])

    df_all["_h"] = df_all["text"].apply(lambda t: hashlib.md5(t.encode()).hexdigest())
    df_all = df_all.drop_duplicates("_h").drop(columns="_h").reset_index(drop=True)

    df_all["y"] = (df_all["label"] == "spam").astype(int)
    df_india["y"] = 1

    print(f"  Email rows: {(df_all.channel=='email').sum()}  |  SMS rows: {(df_all.channel=='sms').sum()}")
    print(f"  India synthetic (train-only): {len(df_india)}")

    # 2. Stratified split 70/15/15 on df_all only
    print("\n[2/6] Splitting data (seed=42, 70/15/15) ...")
    strat_key = df_all["channel"] + "_" + df_all["label"]

    sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    train_idx, temp_idx = next(sss1.split(df_all, strat_key))

    df_temp = df_all.iloc[temp_idx].reset_index(drop=True)
    strat_temp = strat_key.iloc[temp_idx].reset_index(drop=True)

    sss2 = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    val_idx, test_idx = next(sss2.split(df_temp, strat_temp))

    df_train = df_all.iloc[train_idx].reset_index(drop=True)
    df_val   = df_temp.iloc[val_idx].reset_index(drop=True)
    df_test  = df_temp.iloc[test_idx].reset_index(drop=True)

    df_train = pd.concat([df_train, df_india], ignore_index=True)

    print(f"  Train: {len(df_train)}  Val: {len(df_val)}  Test: {len(df_test)}")

    # Verify no test leakage
    train_hashes = set(df_train["text"].apply(lambda t: hashlib.md5(t.encode()).hexdigest()))
    test_hashes  = set(df_test["text"].apply(lambda t: hashlib.md5(t.encode()).hexdigest()))
    overlap = train_hashes & test_hashes
    assert len(overlap) == 0, f"DATA LEAK: {len(overlap)} test rows found in training set!"
    print("  [OK] No train/test overlap")

    X_train, y_train = df_train["text"].tolist(), df_train["y"].tolist()
    X_val,   y_val   = df_val["text"].tolist(),   df_val["y"].tolist()
    X_test,  y_test  = df_test["text"].tolist(),  df_test["y"].tolist()

    # 3. Train models
    print("\n[3/6] Training models ...")
    candidates = {
        "NaiveBayes": MultinomialNB(alpha=0.1),
        "LogisticRegression": LogisticRegression(C=1.0, max_iter=1000, random_state=SEED),
        "RandomForest": RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=SEED),
        "LinearSVM": CalibratedClassifierCV(LinearSVC(C=0.5, max_iter=5000, random_state=SEED)),
    }

    model_results = []
    best_f1, best_name, best_pipeline = -1.0, "", None

    for name, clf in candidates.items():
        t0 = time.time()
        pipe = build_full_pipeline(clf)
        pipe.fit(X_train, y_train)
        train_time = round(time.time() - t0, 2)

        val_pred = pipe.predict(X_val)
        val_prob = pipe.predict_proba(X_val)[:, 1]
        val_f1 = f1_score(y_val, val_pred, zero_division=0)

        print(f"  {name}: val_F1={val_f1:.4f}  train_time={train_time}s")
        model_results.append({"model": name, "val_f1": round(val_f1, 4), "train_time_s": train_time})

        if val_f1 > best_f1:
            best_f1, best_name, best_pipeline = val_f1, name, pipe

    print(f"\n  Best model: {best_name} (val F1={best_f1:.4f})")

    # 4. Test-set evaluation
    print("\n[4/6] Evaluating on test set ...")
    test_pred = best_pipeline.predict(X_test)
    test_prob = best_pipeline.predict_proba(X_test)[:, 1]

    overall = _metrics(best_name, y_test, test_pred, test_prob)
    overall["train_time_s"] = next(r["train_time_s"] for r in model_results if r["model"] == best_name)

    channel_metrics = []
    for ch in ["email", "sms"]:
        mask = df_test["channel"] == ch
        if mask.sum() == 0:
            continue
        idx = mask[mask].index.tolist()
        yt  = [y_test[i] for i in idx]
        yp  = [test_pred[i] for i in idx]
        ypr = [test_prob[i] for i in idx]
        if len(set(yt)) > 1:
            channel_metrics.append(_metrics(best_name, yt, yp, ypr, channel=ch))

    # All-model comparison on val set (refit for fair comparison)
    print("\n  Model comparison (val set) ...")
    all_model_comparison = []
    for name, clf in candidates.items():
        pipe = build_full_pipeline(clf)
        t0 = time.time()
        pipe.fit(X_train, y_train)
        tt = round(time.time() - t0, 2)
        vp  = pipe.predict(X_val)
        vpr = pipe.predict_proba(X_val)[:, 1]
        m = _metrics(name, y_val, vp, vpr)
        m["train_time_s"] = tt
        all_model_comparison.append(m)
        print(f"    {name}: F1={m['f1']}  AUC={m['roc_auc']}  t={tt}s")

    # 5. Save artifacts
    print("\n[5/6] Saving artifacts ...")
    joblib.dump(best_pipeline, ARTIFACTS / "model.joblib")

    metrics = {
        "best_model": best_name,
        "test_metrics_overall": overall,
        "test_metrics_by_channel": channel_metrics,
        "model_comparison_on_val": all_model_comparison,
        "dataset_sizes": {
            "train": int((df_train["channel"] != "sms_india_synthetic").sum()),
            "train_india_synthetic": int((df_train["channel"] == "sms_india_synthetic").sum()),
            "val": len(df_val),
            "test": len(df_test),
            "note": "India synthetic messages used in TRAINING ONLY, never in val/test sets.",
        },
        "split": {"seed": SEED, "ratios": "70/15/15", "stratified_by": "channel+class"},
    }
    (ARTIFACTS / "metrics.json").write_text(json.dumps(metrics, indent=2))

    # Top terms from Logistic Regression
    lr_pipe = build_full_pipeline(
        LogisticRegression(C=1.0, max_iter=1000, random_state=SEED)
    )
    lr_pipe.fit(X_train, y_train)
    tfidf_vec  = lr_pipe.named_steps["features"].transformer_list[0][1]
    lr_clf     = lr_pipe.named_steps["clf"]
    coef       = lr_clf.coef_[0]
    vocab      = tfidf_vec.get_feature_names_out()
    tfidf_coef = coef[:len(vocab)]
    top_spam   = [vocab[i] for i in np.argsort(tfidf_coef)[-20:][::-1]]
    top_ham    = [vocab[i] for i in np.argsort(tfidf_coef)[:20]]
    (ARTIFACTS / "top_terms.json").write_text(
        json.dumps({"top_spam_terms": top_spam, "top_ham_terms": top_ham}, indent=2)
    )

    print(f"  model.joblib   -> {ARTIFACTS / 'model.joblib'}")
    print(f"  metrics.json   -> {ARTIFACTS / 'metrics.json'}")
    print(f"  top_terms.json -> {ARTIFACTS / 'top_terms.json'}")

    # 6. Summary
    print("\n[6/6] Results summary")
    print(f"  Best model : {best_name}")
    print(f"  Test F1    : {overall['f1']}")
    print(f"  Test AUC   : {overall['roc_auc']}")
    print(f"  Test Acc   : {overall['accuracy']}")
    for cm in channel_metrics:
        print(f"  [{cm['channel']}] F1={cm['f1']}  AUC={cm['roc_auc']}")

    if bert:
        print("\n  [BERT] --bert flag detected. DistilBERT fine-tuning is optional/lazy-loaded.")
        print("         Run ml/train_bert.py separately (GPU recommended).")

    print("\nDone. Run: python ml/evaluate.py")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--bert", action="store_true", help="Fine-tune DistilBERT (optional)")
    args = parser.parse_args()
    main(bert=args.bert)
