# PhishGuard

**AI-Powered Phishing Detection and Explainable Risk Analysis System** — a local Flask web application (BCA minor project).

PhishGuard classifies a URL as *Legitimate* or *Phishing* with a machine-learning model, gives a 0–100 risk score, and explains the result with readable indicators. It analyzes the URL **as text only**: it never opens, visits or downloads the submitted address.

Pages: **Dashboard**, **URL Scanner**, **Scan History**.

---

## 1. Setup on Windows

Requires Python 3.11 or newer (tested with 3.13).

```bat
cd path\to\PhishGuard
setup_windows.bat        :: one-time: creates .venv and installs requirements
run.bat                  :: starts the app
```

Then open **http://127.0.0.1:5000**.

Manual equivalent:

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

> **Important – scikit-learn version.** The saved model (`model/phishing_model.pkl`) is a pickle and must be loaded with the scikit-learn version that trained it (1.9.1, pinned in `requirements.txt`). If your installed version differs, the app shows a warning (or "Model offline" with a clear message) instead of silently giving unreliable results. Fix: `python model/train_model.py` (takes seconds).

## 2. Project layout

```
app.py                      Flask routes (Dashboard, Scanner, History)
config.py                   All paths in one place (can be overridden by environment variables)
model/train_model.py        Training + evaluation (writes model + model_report.json)
model/predict.py            Loading/self-check, prediction, classifier explanation
features/indicators.py      Rule-based, human-readable indicators
features/url_features.py    URL structure details shown in the result card
utils/validation.py         URL validation/normalisation
utils/risk.py               Verdict threshold and risk bands (single definition)
utils/database.py           SQLite history + dashboard statistics (+ safe migration)
scripts/prepare_dataset.py  Builds the balanced 10,000-URL dataset
dataset/                    Original 20,000-row Excel file (unchanged) + balanced CSV/XLSX + summary JSON
templates/, static/         Interface (HTML/CSS/JS, no external CDN – works offline)
tests/test_app.py           Automated tests
docs/VIVA.md                Viva explanation
```

## 3. Dataset preparation

```bat
python scripts\prepare_dataset.py
```

Reads `dataset/data_bal - 20000.xlsx` (original is never modified; columns `URLs`, `Labels`; **0 = legitimate, 1 = phishing**) and writes `dataset/phishguard_balanced_10000.csv` (+ `.xlsx` copy, + `_summary.json`). Paths, class size and seed are command-line options (`--help`).

Actual result for the supplied file:

| Step | Count |
|---|---|
| Source rows | 20,000 (10,000 per class) |
| Missing URL / unusable label / conflicting labels | 0 / 0 / 0 |
| Exact duplicate rows | 3 |
| Duplicates removed in total (also ignoring case and a trailing `/`) | 520 |
| Eligible unique URLs | 10,000 legitimate, 9,480 phishing |
| **Final dataset** | **5,000 legitimate + 5,000 phishing = 10,000 unique URLs** (seed 42, reproducible) |

If a class ever has fewer than 5,000 unique URLs the script reports the shortage and uses the smaller number for both classes — it never duplicates or invents rows.

## 4. Training and evaluation

```bat
python model\train_model.py
```

Pipeline: **URL text → character TF-IDF (2–5-grams, 60,000 features) → Logistic Regression.**

* Stratified 80/20 split (seed 42) *before* anything is fitted; the vectorizer is fitted on the training split only.
* The vectorizer and classifier are saved together; prediction uses exactly the same fitted vectorizer (the old "20 features vs 60,000 features" mismatch no longer exists — the 20 structural values are only displayed, never fed to the model).

Held-out test results (2,000 URLs the model never saw):

| Metric | Value |
|---|---|
| Accuracy | 93.5 % |
| Precision (phishing) | 95.9 % |
| Recall (phishing) | 90.9 % |
| F1-score | 93.3 % |
| ROC-AUC | 0.980 |

Confusion matrix: 961 legitimate correct, 39 legitimate flagged as phishing, 91 phishing missed, 909 phishing caught.

Leakage checks: 0 identical URLs appear in both train and test. 18.1 % of test hostnames also occur in training (different pages of the same site) — a normal property of web-URL data that can make scores slightly optimistic.

### A dataset bias that was found and handled

In this dataset 95.8 % of legitimate URLs contain `www.` but only 12.2 % of phishing URLs do. A model trained naively learns "no `www.` ⇒ phishing": it scored 95.6 % on the normal test split, but **only 62 % after removing `www.` from the same test URLs** (just 24 % of legitimate URLs were still recognised), so ordinary addresses like `github.com` would have been flagged. Training therefore adds www-toggled copies of *training* URLs only (`--no-augment` disables this). Cost: normal-test accuracy 95.6 % → 93.5 %; benefit: 93.1 % accuracy and 95.1 % legitimate recall without `www.`. The lower, more robust figure is the honest one to quote.

A balanced dataset fixes class imbalance; it does **not** guarantee real-world accuracy.

## 5. How a result is produced

1. The URL is validated (http/https only, valid host, ≤ 2,048 chars, no spaces); `https://` is added if no scheme is typed.
2. The classifier outputs a **phishing probability**.
3. **Risk score = probability × 100.** **Verdict = Phishing if probability ≥ 50 %**, otherwise Legitimate.
4. Risk levels (presentation aid aligned with the verdict): Low < 25, Medium 25–50 (legitimate, low confidence), High 50–75, Critical ≥ 75. On the test set, the share of real phishing URLs in each band was Low 3 %, Medium 44 %, High 88 %, Critical 98 % (`model/model_report.json` → `band_calibration`), i.e. the bands are ordered sensibly, but the score is *not* a calibrated guarantee.
5. Explanations are shown **separately** and do not change the score:
   * **Rule-based indicators** — IP address host, no HTTPS, `@` in the address, link shorteners, punycode, many sub-domains, security words in the domain or path, custom port, very long URL, many encoded characters, risky file extension, etc., each with the exact text it matched. No indicator proves phishing; none found does not prove safety.
   * **What the classifier noticed** — the character patterns that moved the model's own score the most (tf-idf × coefficient of the linear model), towards phishing or towards legitimate.

## 6. Tests

```bat
python -m unittest discover -s tests -v
```

Covers validation, risk bands, model loading/dimensions, predictions, offline-model handling, indicators, all pages, absence of Methodology, saving scans, dashboard counts, empty/malformed input, HTML escaping, no network access during analysis, database migration of an old `phishguard.db`, and the dataset script (balance, reproducibility, shortage reporting).

## 7. Security notes

* URLs are never fetched or opened and are only shown as escaped text (never as links).
* Input is validated server-side; Flask debug mode is **off** (set `FLASK_DEBUG=1` only while developing); errors show generic messages, no paths or stack traces.
* Security headers/CSP are set; the app listens on `127.0.0.1` only. No secrets or API keys are used.

## 8. Known limitations

* Looks only at the URL text — no page content, DNS/WHOIS, domain age, or blocklists. Phishing on a trusted domain (e.g. a hosted Google Doc) or a brand-new clean-looking domain can be missed; unusual legitimate URLs can be flagged.
* Trained on one 10,000-URL dataset; its URLs are mostly deep links, so bare home pages (e.g. `google.com`) can score in the *Medium* band even though they are classed Legitimate.
* Residual dataset biases remain (e.g. legitimate URLs are 97 % `https` vs 57 % for phishing); only the `www.` shortcut was neutralised.
* Existing `phishguard.db` files are migrated automatically (new columns added, rows kept). Rows from older versions used a different combined score and show no detail breakdown.
* The model pickle depends on the scikit-learn version (see Setup).
* Development server (Flask) — fine for a demonstration, not for production.
