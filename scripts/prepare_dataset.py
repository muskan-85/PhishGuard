"""
Prepare a balanced PhishGuard training dataset.

Reads the original labelled URL file (Excel or CSV), cleans it, removes
duplicates, and writes a reproducible class-balanced sample
(default: 5,000 legitimate + 5,000 phishing URLs).

The original file is never modified.

Usage (from the project folder):
    python scripts/prepare_dataset.py
    python scripts/prepare_dataset.py --per-class 5000 --seed 42
    python scripts/prepare_dataset.py --source "dataset/my_file.xlsx" --out-dir dataset

Run `python scripts/prepare_dataset.py --help` for every option.
"""

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Label spellings that are accepted. Anything else is reported and dropped.
PHISHING_TEXT = {"1", "phishing", "phish", "malicious", "bad", "unsafe"}
LEGIT_TEXT = {"0", "legitimate", "legit", "benign", "good", "safe"}


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", default=str(PROJECT_ROOT / "dataset" / "data_bal - 20000.xlsx"),
                   help="Original dataset (.xlsx or .csv).")
    p.add_argument("--out-dir", default=str(PROJECT_ROOT / "dataset"), help="Output folder.")
    p.add_argument("--out-name", default="phishguard_balanced_10000",
                   help="Output file name without extension.")
    p.add_argument("--url-col", default="URLs", help="Name of the URL column.")
    p.add_argument("--label-col", default="Labels", help="Name of the label column.")
    p.add_argument("--per-class", type=int, default=5000, help="Records to sample per class.")
    p.add_argument("--seed", type=int, default=42, help="Random seed (reproducibility).")
    p.add_argument("--no-xlsx", action="store_true", help="Skip the optional Excel copy.")
    return p.parse_args()


def load_source(path: Path) -> pd.DataFrame:
    if not path.exists():
        sys.exit(f"ERROR: source dataset not found: {path}")
    if path.suffix.lower() in (".xlsx", ".xls"):
        return pd.read_excel(path)
    return pd.read_csv(path)


def normalise_label(value):
    """Return 1 (phishing), 0 (legitimate) or None (unusable)."""
    if pd.isna(value):
        return None
    text = str(value).strip().lower()
    if text.endswith(".0"):          # 1.0 -> 1
        text = text[:-2]
    if text in PHISHING_TEXT:
        return 1
    if text in LEGIT_TEXT:
        return 0
    return None


def url_key(url: str) -> str:
    """Key used to detect duplicates: case-insensitive, ignores a trailing slash."""
    return url.strip().lower().rstrip("/")


def main():
    args = parse_args()
    source = Path(args.source)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_source(source)
    for col in (args.url_col, args.label_col):
        if col not in df.columns:
            sys.exit(f"ERROR: column '{col}' not found. Columns present: {list(df.columns)}")

    summary = {"source_file": source.name, "source_rows": int(len(df)), "seed": args.seed,
               "raw_label_values": {str(k): int(v) for k, v in df[args.label_col].value_counts(dropna=False).items()}}

    # 1. Missing / unusable rows
    df = df[[args.url_col, args.label_col]].rename(columns={args.url_col: "URLs", args.label_col: "Labels"})
    missing_url = df["URLs"].isna() | (df["URLs"].astype(str).str.strip() == "")
    df["Labels"] = df["Labels"].map(normalise_label)
    bad_label = df["Labels"].isna()
    summary["removed_missing_url"] = int(missing_url.sum())
    summary["removed_unusable_label"] = int((bad_label & ~missing_url).sum())
    df = df[~missing_url & ~bad_label].copy()
    df["URLs"] = df["URLs"].astype(str).str.strip()
    df["Labels"] = df["Labels"].astype(int)

    # 2. Conflicting labels: same URL (by key) labelled both ways -> dropped entirely
    df["_key"] = df["URLs"].map(url_key)
    labels_per_key = df.groupby("_key")["Labels"].nunique()
    conflict_keys = set(labels_per_key[labels_per_key > 1].index)
    summary["conflicting_label_urls"] = len(conflict_keys)
    summary["removed_rows_in_conflicts"] = int(df["_key"].isin(conflict_keys).sum())
    df = df[~df["_key"].isin(conflict_keys)]

    # 3. Duplicates (exact, then near-duplicates by key)
    summary["exact_duplicate_rows"] = int(df.duplicated(subset="URLs").sum())
    before = len(df)
    df = df.drop_duplicates(subset="_key", keep="first")
    summary["removed_duplicates_total"] = int(before - len(df))
    summary["near_duplicates_only"] = summary["removed_duplicates_total"] - summary["exact_duplicate_rows"]

    available = df["Labels"].value_counts().to_dict()
    summary["eligible_unique_legitimate"] = int(available.get(0, 0))
    summary["eligible_unique_phishing"] = int(available.get(1, 0))

    # 4. Balanced sample (never duplicates or invents rows)
    shortage = {name: args.per_class - available.get(code, 0)
                for name, code in (("legitimate", 0), ("phishing", 1))
                if available.get(code, 0) < args.per_class}
    if shortage:
        n = min(available.get(0, 0), available.get(1, 0))
        summary["warning"] = (f"Not enough unique records for {args.per_class} per class "
                              f"(shortage: {shortage}). Using {n} per class instead.")
        print("WARNING:", summary["warning"])
    else:
        n = args.per_class

    parts = [df[df["Labels"] == c].sample(n=n, random_state=args.seed) for c in (0, 1)]
    final = (pd.concat(parts)[["URLs", "Labels"]]
             .sample(frac=1, random_state=args.seed).reset_index(drop=True))

    # 5. Save
    csv_path = out_dir / f"{args.out_name}.csv"
    final.to_csv(csv_path, index=False, encoding="utf-8")
    outputs = {"csv": csv_path.name}
    if not args.no_xlsx:
        xlsx_path = out_dir / f"{args.out_name}.xlsx"
        final.to_excel(xlsx_path, index=False)
        outputs["xlsx"] = xlsx_path.name
    summary["final_rows"] = int(len(final))
    summary["final_legitimate"] = int((final["Labels"] == 0).sum())
    summary["final_phishing"] = int((final["Labels"] == 1).sum())
    summary["final_unique_urls"] = int(final["URLs"].nunique())
    summary["label_mapping"] = "0 = legitimate, 1 = phishing"
    summary["outputs"] = outputs

    summary_path = out_dir / f"{args.out_name}_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\nPhishGuard dataset preparation")
    print("------------------------------")
    for k, v in summary.items():
        print(f"{k:28}: {v}")
    print(f"\nSaved: {csv_path}")


if __name__ == "__main__":
    main()
