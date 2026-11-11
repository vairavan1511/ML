"""Shared feature extraction: TF-IDF (1-2 grams, 30k) + 7 handcrafted features."""
from __future__ import annotations

import re
import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.base import BaseEstimator, TransformerMixin

URGENCY_WORDS = {
    "urgent", "immediately", "verify", "suspend", "blocked", "expire",
    "confirm", "alert", "warning", "limited", "act now", "click here",
    "otp", "kyc", "upi", "account", "prize", "winner", "lottery",
    "congratulations", "free", "offer", "loan", "job",
}

CURRENCY_RE = re.compile(r"[$€£₹¥₩]")
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
DIGIT_RE = re.compile(r"\d")
UPPER_RE = re.compile(r"[A-Z]")


class HandcraftedFeatures(BaseEstimator, TransformerMixin):
    """7 numeric features: log_len, url_count, digit_ratio, upper_ratio,
    exclamation_count, currency_count, urgency_count."""

    def fit(self, X, y=None):  # noqa: N803
        return self

    def transform(self, X, y=None):  # noqa: N803
        return np.array([self._featurize(t) for t in X], dtype=np.float32)

    @staticmethod
    def _featurize(text: str) -> list[float]:
        n = max(len(text), 1)
        lower = text.lower()
        return [
            np.log1p(n),
            len(URL_RE.findall(text)),
            len(DIGIT_RE.findall(text)) / n,
            len(UPPER_RE.findall(text)) / n,
            text.count("!"),
            len(CURRENCY_RE.findall(text)),
            sum(1 for w in URGENCY_WORDS if w in lower),
        ]


def build_pipeline() -> Pipeline:
    """Return an unfitted sklearn Pipeline (TF-IDF + handcrafted → classifier slot)."""
    tfidf = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=30_000,
        sublinear_tf=True,
        strip_accents="unicode",
        min_df=2,
    )
    union = FeatureUnion([
        ("tfidf", tfidf),
        ("hand", HandcraftedFeatures()),
    ])
    # Scaler applied only to handcrafted block via a wrapper below
    return union  # caller wraps with classifier


def build_full_pipeline(clf) -> Pipeline:
    """Wrap feature union + scaler-on-handcrafted + classifier into one Pipeline."""
    return Pipeline([
        ("features", build_pipeline()),
        ("clf", clf),
    ])
