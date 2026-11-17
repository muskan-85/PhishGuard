"""
Train the PhishGuard classifier: character TF-IDF + Logistic Regression.

Pipeline (same one used at prediction time):
    URL text -> TfidfVectorizer(char 2-5 grams) -> LogisticRegression

Good practice followed here:
  * stratified, seeded train/test split BEFORE anything is fitted
  * the TF-IDF vectorizer is fitted on the training split only
  * duplicate / leakage checks between train and test
  * accuracy, precision, recall, F1, ROC-AUC and a confusion matrix

Usage (from the project folder):
    python model/train_model.py
    python model/train_model.py --data dataset/phishguard_balanced_10000.csv --seed 42
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

import config
from utils.risk import DECISION_THRESHOLD, RISK_BANDS

MODEL_NAME = "Character TF-IDF + Logistic Regression"


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default=str(config.DATASET_PATH), help="Training dataset (.csv or .xlsx).")
    p.add_argument("--model-out", default=str(config.MODEL_PATH), help="Where to save the model.")
    p.add_argument("--report-out", default=str(config.MODEL_REPORT_PATH), help="Where to save the JSON report.")
    p.add_argument("--test-size", type=float, default=0.20)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-features", type=int, default=60000)
    p.add_argument("--no-augment", action="store_true",
                   help="Disable the www-invariance augmentation of the training split.")
    return p.parse_args()


def load_data(path):
    if not os.path.exists(path):
        sys.exit(f"ERROR: dataset not found: {path}\nRun: python scripts/prepare_dataset.py")
    df = pd.read_excel(path) if path.lower().endswith((".xlsx", ".xls")) else pd.read_csv(path)
    missing = {"URLs", "Labels"} - set(df.columns)
    if missing:
        sys.exit(f"ERROR: dataset must contain columns 'URLs' and 'Labels' (missing: {missing})")
    df = df.dropna(subset=["URLs", "Labels"]).copy()
    df["URLs"] = df["URLs"].astype(str).str.strip()
    df["Labels"] = df["Labels"].astype(int)
    if set(df["Labels"].unique()) - {0, 1}:
        sys.exit("ERROR: Labels must be 0 (legitimate) or 1 (phishing).")
    return df


def hostname_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


_IPV4_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def toggle_www(url):
    """Return the URL with a leading 'www.' removed, or added to a plain two-label domain.

    Returns None when no sensible variant exists (IP hosts, deep sub-domains, ...).
    Whether a site writes 'www.' says nothing about whether it is malicious, but in
    this dataset 96% of legitimate URLs have it versus 12% of phishing URLs. Training on
    both variants stops the model from using it as a shortcut.
    """
    m = re.match(r"^(https?://)(www\.)(.+)$", url, re.IGNORECASE)
    if m:
        return m.group(1) + m.group(3)
    m = re.match(r"^(https?://)([^/?#:@]+)(.*)$", url, re.IGNORECASE)
    if m and not _IPV4_HOST.match(m.group(2)) and m.group(2).count(".") == 1:
        return m.group(1) + "www." + m.group(2) + m.group(3)
    return None


def main():
    args = parse_args()
    df = load_data(args.data)
    n_dupes = int(df["URLs"].str.lower().str.rstrip("/").duplicated().sum())
    print(f"Loaded {len(df)} rows from {args.data}  (duplicate URLs: {n_dupes})")
    print("Class counts:", df["Labels"].value_counts().sort_index().to_dict(), "(0=legitimate, 1=phishing)")

    # 1. Split first - nothing is fitted on the test data.
    X_train, X_test, y_train, y_test = train_test_split(
        df["URLs"], df["Labels"], test_size=args.test_size,
        random_state=args.seed, stratify=df["Labels"])

    # 2. Leakage checks
    exact_overlap = len(set(X_train) & set(X_test))
    train_hosts = {hostname_of(u) for u in X_train}
    test_hosts = [hostname_of(u) for u in X_test]
    host_overlap_pct = 100.0 * np.mean([h in train_hosts for h in test_hosts])

    # 3. (Optional) augment the TRAINING split only with www-toggled copies.
    n_original_train = len(X_train)
    if not args.no_augment:
        variants = X_train.map(toggle_www)
        keep = variants.notna()
        X_train = pd.concat([X_train, variants[keep]], ignore_index=True)
        y_train = pd.concat([y_train, y_train[keep]], ignore_index=True)
        print(f"Augmented training split: {n_original_train} -> {len(X_train)} rows (test split untouched)")

    # 4. Fit vectorizer on the TRAINING split only, then the classifier.
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=2,
                                 max_features=args.max_features, sublinear_tf=True)
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train_vec, y_train)

    # 5. Evaluation on the untouched test split
    proba = model.predict_proba(X_test_vec)[:, 1]
    pred = (proba >= DECISION_THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
    metrics = {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred)),
        "recall": float(recall_score(y_test, pred)),
        "f1": float(f1_score(y_test, pred)),
        "roc_auc": float(roc_auc_score(y_test, proba)),
    }
    confusion = {"true_negative": int(tn), "false_positive": int(fp),
                 "false_negative": int(fn), "true_positive": int(tp)}

    # 6. Do the risk bands mean something? Share of real phishing per band.
    score = proba * 100
    band_calibration = []
    upper = 100.0001
    for lower, label in RISK_BANDS:
        mask = (score >= lower) & (score < upper)
        n = int(mask.sum())
        band_calibration.append({
            "band": label, "range": f"{lower:g}-{min(upper, 100):g}", "test_urls": n,
            "actual_phishing_pct": round(float(y_test.values[mask].mean() * 100), 1) if n else None})
        upper = lower
    band_calibration.reverse()

    # 7. Honest sensitivity check: the dataset is biased towards "www." for legitimate sites.
    def strip_www(u):
        return u.replace("://www.", "://", 1)
    X_test_nowww = X_test.map(strip_www)
    pred_nowww = (model.predict_proba(vectorizer.transform(X_test_nowww))[:, 1] >= DECISION_THRESHOLD).astype(int)
    www_share = df.assign(www=df["URLs"].str.contains("://www.", regex=False)).groupby("Labels")["www"].mean()
    sensitivity = {
        "share_with_www_legitimate_pct": round(float(www_share.get(0, 0) * 100), 1),
        "share_with_www_phishing_pct": round(float(www_share.get(1, 0) * 100), 1),
        "test_accuracy_after_removing_www": round(float(accuracy_score(y_test, pred_nowww)), 4),
        "legitimate_recall_after_removing_www": round(float(
            recall_score(y_test, pred_nowww, pos_label=0)), 4),
    }

    report = {
        "model_name": MODEL_NAME,
        "trained_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "sklearn_version": sklearn.__version__,
        "dataset_file": os.path.basename(args.data),
        "dataset_rows": int(len(df)),
        "dataset_legitimate": int((df["Labels"] == 0).sum()),
        "dataset_phishing": int((df["Labels"] == 1).sum()),
        "train_rows_original": int(n_original_train), "train_rows_after_augmentation": int(len(X_train)),
        "www_augmentation": not args.no_augment, "test_rows": int(len(X_test)),
        "test_size": args.test_size, "seed": args.seed,
        "tfidf_features": int(len(vectorizer.vocabulary_)),
        "metrics": metrics, "confusion_matrix": confusion,
        "leakage_checks": {"exact_urls_in_train_and_test": exact_overlap,
                           "test_hostnames_also_in_train_pct": round(float(host_overlap_pct), 1),
                           "duplicate_urls_in_dataset": n_dupes},
        "band_calibration": band_calibration,
        "dataset_bias_check": sensitivity,
        "decision_threshold": DECISION_THRESHOLD,
    }

    print(f"\n{MODEL_NAME}\n" + "-" * 40)
    for k, v in metrics.items():
        print(f"{k:10}: {v:.4f}")
    print("Confusion matrix (rows=actual, cols=predicted):")
    print(f"            pred legit  pred phishing\n  actual legit   {tn:6d}      {fp:6d}\n  actual phish   {fn:6d}      {tp:6d}")
    print("Leakage: exact URLs in both splits =", exact_overlap,
          "| test hostnames also seen in training =", f"{host_overlap_pct:.1f}%")
    print("Risk-band check:", band_calibration)
    print("Dataset bias check:", sensitivity)

    # 8. Save model + vectorizer together (they must always travel as a pair).
    joblib.dump({"vectorizer": vectorizer, "model": model, "model_name": MODEL_NAME,
                 "sklearn_version": sklearn.__version__, "training_metrics": metrics,
                 "feature_count": int(X_train_vec.shape[1])}, args.model_out)
    with open(args.report_out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print("\nSaved model :", args.model_out)
    print("Saved report:", args.report_out)


if __name__ == "__main__":
    main()
