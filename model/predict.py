"""
Prediction pipeline.

    URL -> validate/normalise -> saved TfidfVectorizer -> saved LogisticRegression
        -> phishing probability -> verdict + risk score

The classifier is the ONLY thing that decides the verdict and the risk score.
Rule-based indicators (features/indicators.py) are reported alongside, separately.

The URL is never opened or fetched: it is only treated as text.
"""

import os
import sys
import warnings

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
import numpy as np
import sklearn

import config
from features.indicators import analyze_indicators
from features.url_features import extract_features
from utils.risk import DECISION_THRESHOLD, get_risk_level, get_verdict
from utils.validation import validate_url

TOP_NGRAMS = 6


class ModelLoadError(RuntimeError):
    """The model could not be loaded or failed its self-check."""


_state = {"loaded": False, "bundle": None, "error": None, "warning": None, "feature_names": None}


def _load():
    """Load and self-check the model once. Records the outcome instead of crashing the app."""
    if _state["loaded"]:
        return
    _state["loaded"] = True
    try:
        if not config.MODEL_PATH.exists():
            raise ModelLoadError(
                "Model file not found. Train it with:  python model/train_model.py")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                bundle = joblib.load(config.MODEL_PATH)
            except Exception as exc:
                raise ModelLoadError(
                    f"Model file could not be loaded ({type(exc).__name__}). "
                    "It was probably saved with a different scikit-learn version. "
                    "Re-train with:  python model/train_model.py") from exc

        if not isinstance(bundle, dict) or "model" not in bundle or "vectorizer" not in bundle:
            raise ModelLoadError("Model file does not contain both a 'model' and a 'vectorizer'. "
                                 "Re-train with:  python model/train_model.py")
        vectorizer, model = bundle["vectorizer"], bundle["model"]

        n_vec = len(vectorizer.vocabulary_)
        n_model = model.coef_.shape[1]
        if n_vec != n_model:
            raise ModelLoadError(
                f"Feature mismatch: vectorizer produces {n_vec} features but the classifier expects "
                f"{n_model}. Re-train with:  python model/train_model.py")

        # Smoke test: a real prediction must work.
        try:
            p = model.predict_proba(vectorizer.transform(["https://www.example.com/"]))[0][1]
            if not 0.0 <= float(p) <= 1.0:
                raise ValueError("probability out of range")
        except Exception as exc:
            raise ModelLoadError(f"Model self-test failed ({type(exc).__name__}). "
                                 "Re-train with:  python model/train_model.py") from exc

        trained_with = bundle.get("sklearn_version")
        if any("Inconsistent" in type(w.message).__name__ for w in caught) or (
                trained_with and trained_with != sklearn.__version__):
            _state["warning"] = (
                f"Model was trained with scikit-learn {trained_with or 'an older version'}, "
                f"but {sklearn.__version__} is installed. Results may be unreliable - "
                "re-train with:  python model/train_model.py")

        _state["bundle"] = bundle
        _state["feature_names"] = vectorizer.get_feature_names_out()
    except ModelLoadError as exc:
        _state["error"] = str(exc)


def get_status():
    """Real model state for the UI: state is 'online', 'warning' or 'offline'."""
    _load()
    if _state["error"]:
        return {"state": "offline", "message": _state["error"], "model_name": None}
    bundle = _state["bundle"]
    state = "warning" if _state["warning"] else "online"
    return {"state": state,
            "message": _state["warning"] or "Classifier and vectorizer loaded and verified.",
            "model_name": bundle.get("model_name", "TF-IDF + Logistic Regression"),
            "feature_count": len(bundle["vectorizer"].vocabulary_)}


def reset_for_tests():
    _state.update({"loaded": False, "bundle": None, "error": None, "warning": None, "feature_names": None})


def _top_ngrams(x_row, vectorizer, model):
    """Character patterns that pushed this URL's score up/down.

    Logistic regression is linear, so each present n-gram contributes
    (tf-idf value x coefficient) to the score: positive = towards phishing.
    """
    coo = x_row.tocoo()
    contrib = coo.data * model.coef_[0][coo.col]
    names = _state["feature_names"][coo.col]
    order = np.argsort(contrib)

    def pick(indices, positive):
        """Strongest patterns first; skip ones that overlap an already chosen pattern
        (e.g. keep 'login' and drop 'ogin') so the list stays readable."""
        chosen = []
        for i in indices:
            if (contrib[i] > 0) != positive:
                break
            pattern = str(names[i])
            if any(pattern in c["pattern"] or c["pattern"] in pattern for c in chosen):
                continue
            chosen.append({"pattern": pattern, "weight": round(float(contrib[i]), 3)})
            if len(chosen) == TOP_NGRAMS:
                break
        return chosen

    return pick(order[::-1], True), pick(order, False)


def predict_url(raw_url):
    """Analyse one URL. Raises InvalidURLError (bad input) or ModelLoadError (model unavailable)."""
    url = validate_url(raw_url)
    _load()
    if _state["error"]:
        raise ModelLoadError(_state["error"])

    bundle = _state["bundle"]
    vectorizer, model = bundle["vectorizer"], bundle["model"]

    x = vectorizer.transform([url])
    probability = float(model.predict_proba(x)[0][1])
    score = round(probability * 100, 1)
    toward_phish, toward_legit = _top_ngrams(x, vectorizer, model)

    return {
        "url": url,
        "verdict": get_verdict(probability),
        "probability": round(probability, 4),
        "risk_score": score,
        "risk_level": get_risk_level(score),
        "threshold": DECISION_THRESHOLD,
        "indicators": analyze_indicators(url),
        "ngrams_phishing": toward_phish,
        "ngrams_legitimate": toward_legit,
        "structure": extract_features(url),
        "model_name": bundle.get("model_name"),
        "model_warning": _state["warning"],
    }
