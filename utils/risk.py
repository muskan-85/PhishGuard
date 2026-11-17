"""Single place where the verdict threshold and risk bands are defined.

Risk score = classifier phishing probability x 100.
Verdict    = "Phishing" when probability >= DECISION_THRESHOLD, else "Legitimate".

The four risk bands are only a presentation aid. They are lined up with the
decision threshold so that the band never contradicts the verdict:
    Low / Medium   -> Legitimate
    High / Critical -> Phishing
Whether the bands are meaningful is checked at training time: model/train_model.py
reports the share of real phishing URLs found in each band of the test set
(see model/model_report.json -> "band_calibration").
"""

DECISION_THRESHOLD = 0.50

# (lower bound in %, label) - checked from the top down
RISK_BANDS = (
    (75.0, "Critical Risk"),
    (50.0, "High Risk"),
    (25.0, "Medium Risk"),
    (0.0, "Low Risk"),
)


def get_verdict(probability: float) -> str:
    return "Phishing" if probability >= DECISION_THRESHOLD else "Legitimate"


def get_risk_level(score: float) -> str:
    """score is on the 0-100 scale."""
    for lower, label in RISK_BANDS:
        if score >= lower:
            return label
    return "Low Risk"
