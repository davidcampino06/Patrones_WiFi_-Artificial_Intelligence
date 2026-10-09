import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app import preprocessing
from app.preprocessing import FEATURES
from app.schemas import AnalysisRequest, AnalysisResponse, ModelInfo, Severity

logger = logging.getLogger(__name__)

MODEL_VERSION = "isolation-forest-1.0"
TRAINING_SOURCE = "synthetic baseline of normal Wi-Fi behaviour (simulated data)"

# Direction in which a deviation is harmful: +1 higher is worse, -1 lower is worse.
HARMFUL_DIRECTION = {
    "latency": 1, "jitter": 1, "packet_loss": 1, "bandwidth": -1, "signal_strength": -1,
    "traffic_volume": 1, "connected_devices": 1, "packet_count": 1,
}

RECOMMENDATIONS = {
    "latency": "Check channel congestion and the uplink/backhaul of the access point.",
    "jitter": "Review QoS settings and interference on the current channel.",
    "packet_loss": "Inspect radio interference and retransmissions; consider changing channel.",
    "bandwidth": "Verify ISP link capacity and per-client bandwidth limits.",
    "signal_strength": "Reposition the access point or add coverage in this zone.",
    "traffic_volume": "Inspect traffic for unusual bulk transfers.",
    "connected_devices": "Balance clients across access points or add capacity.",
    "packet_count": "Look for scanning or flooding behaviour in the traffic capture.",
}

DEVIATION_LIMIT = 2.0


def generate_baseline(samples: int = 5000, seed: int = 42) -> pd.DataFrame:
    """Simulated measurements of healthy networks used to fit the baseline model."""
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "latency": rng.lognormal(np.log(20), 0.45, samples),
        "jitter": rng.lognormal(np.log(4), 0.5, samples),
        "packet_loss": np.clip(rng.exponential(0.4, samples), 0, 100),
        "bandwidth": rng.lognormal(np.log(250), 0.6, samples),
        "signal_strength": np.clip(rng.normal(-58, 8, samples), -95, -30),
        "traffic_volume": rng.lognormal(np.log(220), 0.6, samples),
        "connected_devices": rng.poisson(30, samples).astype(float),
        "packet_count": rng.lognormal(np.log(180_000), 0.5, samples),
    })


class AnomalyDetectionService:
    def __init__(self, model: IsolationForest, medians: pd.Series, spreads: pd.Series,
                 raw_medians: dict[str, float]):
        self._model = model
        self._medians = medians
        self._spreads = spreads
        self._raw_medians = raw_medians

    @classmethod
    def train(cls, baseline: pd.DataFrame, seed: int = 42) -> "AnomalyDetectionService":
        features = preprocessing.transform(baseline)
        model = IsolationForest(n_estimators=200, contamination=0.02, random_state=seed)
        model.fit(features)
        spreads = features.quantile(0.75) - features.quantile(0.25)
        return cls(model, features.median(), spreads, baseline.median().to_dict())

    @classmethod
    def load_or_train(cls, path: str) -> "AnomalyDetectionService":
        model_path = Path(path)
        if model_path.exists():
            logger.info("Loading model from %s", model_path)
            return cls(**joblib.load(model_path))
        logger.info("No model at %s, training baseline model", model_path)
        service = cls.train(generate_baseline())
        model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(service._state(), model_path)
        return service

    @property
    def threshold(self) -> float:
        # Samples whose normalized score exceeds this are outliers for the fitted contamination.
        return float(-self._model.offset_)

    def detect(self, request: AnalysisRequest) -> AnalysisResponse:
        raw = preprocessing.to_frame(request.measurements)
        raw, imputed = preprocessing.impute(raw, self._raw_medians)
        features = preprocessing.transform(raw)

        scores = -self._model.score_samples(features)
        outliers = self._model.predict(features) == -1
        latest_score = float(scores[-1])
        detected = bool(outliers[-1])
        contributors = self._contributors(features.iloc[-1])

        return AnalysisResponse(
            anomaly_detected=detected,
            anomaly_score=round(min(max(latest_score, 0.0), 1.0), 4),
            severity=self._severity(latest_score) if detected else Severity.NONE,
            message=self._message(detected, contributors, int(outliers.sum()), len(scores)),
            recommendation=self._recommendation(contributors) if detected else None,
            contributing_features=contributors,
            anomalous_samples=int(outliers.sum()),
            sample_size=len(scores),
            imputed_features=imputed,
            model_version=MODEL_VERSION,
            simulated_data=request.simulated_data,
        )

    def info(self) -> ModelInfo:
        return ModelInfo(algorithm="IsolationForest", model_version=MODEL_VERSION, features=FEATURES,
                         threshold=round(self.threshold, 4), trained_on=TRAINING_SOURCE)

    def _severity(self, score: float) -> Severity:
        margin = score - self.threshold
        if margin >= 0.10:
            return Severity.HIGH
        if margin >= 0.04:
            return Severity.MEDIUM
        return Severity.LOW

    def _contributors(self, sample: pd.Series) -> list[str]:
        deviation = preprocessing.robust_deviation(sample, self._medians, self._spreads)
        harmful = {f: deviation[f] * HARMFUL_DIRECTION[f] for f in FEATURES}
        flagged = [f for f, value in harmful.items() if value > DEVIATION_LIMIT]
        return sorted(flagged, key=harmful.get, reverse=True)

    @staticmethod
    def _message(detected: bool, contributors: list[str], outliers: int, total: int) -> str:
        if not detected:
            return f"Latest measurement within normal behaviour ({outliers}/{total} outliers in window)"
        if contributors:
            return f"Unusual network behaviour detected in: {', '.join(contributors)}"
        return "Unusual combination of metrics detected"

    @staticmethod
    def _recommendation(contributors: list[str]) -> str:
        if not contributors:
            return "Review recent configuration changes and compare with previous measurements."
        return " ".join(RECOMMENDATIONS[f] for f in contributors[:2])

    def _state(self) -> dict:
        return {"model": self._model, "medians": self._medians, "spreads": self._spreads,
                "raw_medians": self._raw_medians}
