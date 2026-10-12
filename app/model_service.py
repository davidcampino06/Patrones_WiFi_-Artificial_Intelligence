import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app import diagnosis, preprocessing
from app.diagnosis import AnomalyType
from app.preprocessing import FEATURES
from app.schemas import AnalysisRequest, AnalysisResponse, ModelInfo, Severity

logger = logging.getLogger(__name__)

MODEL_VERSION = "isolation-forest-1.1"
TRAINING_SOURCE = "línea base sintética de comportamiento Wi-Fi normal (datos simulados)"

# Direction in which a deviation is harmful: +1 higher is worse, -1 lower is worse.
HARMFUL_DIRECTION = {
    "latency": 1, "jitter": 1, "packet_loss": 1, "bandwidth": -1, "signal_strength": -1,
    "traffic_volume": 1, "connected_devices": 1, "packet_count": 1,
}

FEATURE_LABELS = {
    "latency": "latencia", "jitter": "jitter", "packet_loss": "pérdida de paquetes", "bandwidth": "ancho de banda",
    "signal_strength": "intensidad de señal", "traffic_volume": "volumen de tráfico",
    "connected_devices": "dispositivos conectados", "packet_count": "cantidad de paquetes",
}

RECOMMENDATIONS = {
    "latency": "Revisa la congestión del canal y el enlace de salida (backhaul) del punto de acceso.",
    "jitter": "Revisa la configuración de QoS y la interferencia en el canal actual.",
    "packet_loss": "Revisa interferencias de radio y retransmisiones; considera cambiar de canal.",
    "bandwidth": "Verifica la capacidad del enlace del proveedor y los límites de ancho de banda por cliente.",
    "signal_strength": "Reubica el punto de acceso o agrega cobertura en esta zona.",
    "traffic_volume": "Revisa el tráfico en busca de transferencias masivas inusuales.",
    "connected_devices": "Distribuye los clientes entre puntos de acceso o agrega capacidad.",
    "packet_count": "Busca comportamientos de escaneo o inundación en la captura de tráfico.",
}

DEVIATION_LIMIT = 2.0

# Hyperparameters chosen with app.evaluation on a validation set (see docs/evaluacion_modelos.md): each tree sees
# the whole baseline instead of the default 256 samples, which raised recall on mild provider and traffic faults.
N_ESTIMATORS = 200
CONTAMINATION = 0.02
MAX_SAMPLES = 1.0

# Distance above the threshold that separates LOW < MEDIUM < HIGH severity.
MEDIUM_MARGIN = 0.08
HIGH_MARGIN = 0.17


def build_model(n_estimators: int = N_ESTIMATORS, max_samples: float | int | str = MAX_SAMPLES,
                contamination: float = CONTAMINATION, seed: int = 42) -> IsolationForest:
    return IsolationForest(n_estimators=n_estimators, max_samples=max_samples, contamination=contamination,
                           random_state=seed)


def harmful_deviations(sample: pd.Series, medians: pd.Series, spreads: pd.Series) -> dict[str, float]:
    """Robust deviation of each feature, signed so that a positive value always means worse."""
    deviation = preprocessing.robust_deviation(sample, medians, spreads)
    return {f: float(deviation[f]) * HARMFUL_DIRECTION[f] for f in FEATURES}


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
        model = build_model(seed=seed)
        model.fit(features)
        spreads = features.quantile(0.75) - features.quantile(0.25)
        return cls(model, features.median(), spreads, baseline.median().to_dict())

    @classmethod
    def load_or_train(cls, path: str) -> "AnomalyDetectionService":
        model_path = Path(path)
        if model_path.exists():
            state = joblib.load(model_path)
            if state.pop("version", None) == MODEL_VERSION:
                logger.info("Loading model from %s", model_path)
                return cls(**state)
            logger.info("Model at %s is from another version, retraining", model_path)
        else:
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
        outliers = self.flag(features)
        latest_score = float(scores[-1])
        detected = bool(outliers[-1])
        harmful = self.deviations(features.iloc[-1])
        contributors = self._contributors(harmful)
        anomaly_type = diagnosis.diagnose(harmful) if detected else AnomalyType.NONE

        return AnalysisResponse(
            anomaly_detected=detected,
            anomaly_score=round(min(max(latest_score, 0.0), 1.0), 4),
            severity=self._severity(latest_score) if detected else Severity.NONE,
            anomaly_type=anomaly_type,
            diagnosis=diagnosis.describe(anomaly_type),
            message=self._message(detected, anomaly_type, contributors, int(outliers.sum()), len(scores)),
            recommendation=self._recommendation(anomaly_type, contributors) if detected else None,
            contributing_features=contributors,
            feature_deviations={f: round(value, 2) for f, value in harmful.items()},
            anomalous_samples=int(outliers.sum()),
            sample_size=len(scores),
            imputed_features=imputed,
            model_version=MODEL_VERSION,
            simulated_data=request.simulated_data,
        )

    def flag(self, features: pd.DataFrame) -> np.ndarray:
        """True for each transformed sample the model considers an outlier."""
        return self._model.predict(features) == -1

    def deviations(self, sample: pd.Series) -> dict[str, float]:
        return harmful_deviations(sample, self._medians, self._spreads)

    def info(self, recommendation_engine: str = "reglas") -> ModelInfo:
        return ModelInfo(algorithm="IsolationForest", model_version=MODEL_VERSION, features=FEATURES,
                         threshold=round(self.threshold, 4), trained_on=TRAINING_SOURCE,
                         recommendation_engine=recommendation_engine)

    def _severity(self, score: float) -> Severity:
        margin = score - self.threshold
        if margin >= HIGH_MARGIN:
            return Severity.HIGH
        if margin >= MEDIUM_MARGIN:
            return Severity.MEDIUM
        return Severity.LOW

    @staticmethod
    def _contributors(harmful: dict[str, float]) -> list[str]:
        flagged = [f for f, value in harmful.items() if value > DEVIATION_LIMIT]
        return sorted(flagged, key=harmful.get, reverse=True)

    @staticmethod
    def _message(detected: bool, anomaly_type: AnomalyType, contributors: list[str], outliers: int,
                 total: int) -> str:
        if not detected:
            return f"La última medición está dentro del comportamiento normal ({outliers}/{total} valores atípicos en la ventana)"
        labels = ", ".join(FEATURE_LABELS[f] for f in contributors)
        if anomaly_type != AnomalyType.UNKNOWN:
            cause = f"Posible {diagnosis.LABELS[anomaly_type]}"
            return f"{cause}: {labels}" if labels else cause
        if labels:
            return f"Comportamiento inusual detectado en: {labels}"
        return "Se detectó una combinación inusual de métricas"

    @staticmethod
    def _recommendation(anomaly_type: AnomalyType, contributors: list[str]) -> str:
        if anomaly_type != AnomalyType.UNKNOWN:
            return diagnosis.ACTIONS[anomaly_type]
        if not contributors:
            return diagnosis.ACTIONS[AnomalyType.UNKNOWN]
        return " ".join(RECOMMENDATIONS[f] for f in contributors[:2])

    def _state(self) -> dict:
        return {"model": self._model, "medians": self._medians, "spreads": self._spreads,
                "raw_medians": self._raw_medians, "version": MODEL_VERSION}
