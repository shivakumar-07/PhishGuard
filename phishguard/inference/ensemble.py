"""Soft-voting ensemble over *pre-fitted* pipelines.

sklearn's VotingClassifier refits every estimator, which doubles training
time when we also want standalone metrics per model. This thin wrapper
averages predict_proba over already-fitted pipelines instead (optionally
weighted), which is mathematically identical to soft voting.
"""
from __future__ import annotations

import numpy as np


class SoftVotingEnsemble:
    """Average predict_proba of pre-fitted estimators (soft voting)."""

    def __init__(self, estimators, weights=None):
        # estimators: list[(name, fitted_pipeline)]
        self.estimators = estimators
        self.weights = weights
        self.classes_ = np.array([0, 1])

    def predict_proba(self, X) -> np.ndarray:
        probas = [est.predict_proba(X) for _, est in self.estimators]
        return np.average(probas, axis=0, weights=self.weights)

    def predict(self, X) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)

    @property
    def named_estimators(self):
        return dict(self.estimators)
