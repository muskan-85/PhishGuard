# PhishGuard – Viva explanation

**What is it?** A local web app that tells you whether a URL looks like phishing, shows a 0–100 risk score, and explains why. It only reads the URL text; it never opens the site.

**Architecture (3 layers)**
1. *Interface* – Flask + HTML/CSS/JS: Dashboard, URL Scanner, Scan History.
2. *Analysis* – validation → TF-IDF vectorizer → Logistic Regression → probability; plus a separate rule-based indicator engine.
3. *Storage* – SQLite table `scans` (history and dashboard numbers come only from here).

**How classification works**
- A URL is just text. Character n-grams (2–5 characters, e.g. `logi`, `.php`, `-sec`) are counted and weighted by TF-IDF → a sparse vector of 60,000 numbers.
- Logistic Regression learned, from 8,000 labelled URLs (+ augmentation), a weight for every pattern. It adds the weights and converts the sum to a probability between 0 and 1.
- Risk score = probability × 100. Probability ≥ 50 % → *Phishing*, otherwise *Legitimate*.

**Why these choices?** TF-IDF + Logistic Regression is simple, fast, runs locally, and is a *linear* model, so its decision can be explained: each pattern's weight × tf-idf value shows what pushed the score up or down.

**Explainability** – two separate things: (1) the model's strongest patterns for this URL; (2) rule-based checks (IP host, no HTTPS, `@`, shortener, many sub-domains, security words…). The rules do not change the score.

**Dataset** – 20,000 labelled URLs → remove duplicates → random sample of 5,000 legitimate + 5,000 phishing (fixed seed). Split 80/20 *before* fitting so the test data is truly unseen.

**Results** – test accuracy 93.5 %, precision 95.9 %, recall 90.9 %, F1 93.3 %. Be ready to say: precision = of the URLs called phishing, how many really were; recall = of all real phishing, how many were caught.

**A good point to mention** – the dataset had a shortcut (96 % of legitimate URLs contain `www.`); the first model fell to 62 % accuracy once `www.` was removed, so training was augmented to fix it (accuracy 93.1 % without `www.`).

**Limitations** – URL text only; one dataset; not a guarantee; cannot judge page content or domain age.

**Likely questions**
- *Why not just rules?* Attackers vary patterns; ML learns combinations from data. Rules are kept for human-readable reasons.
- *Is 93.5 % reliable in real life?* No – it is measured on a held-out part of this dataset only.
- *Why precision and recall, not only accuracy?* A missed phishing URL and a false alarm have different costs.
- *Does it visit the link?* No – analysis is text-only, so it is safe to test with dangerous-looking links.
