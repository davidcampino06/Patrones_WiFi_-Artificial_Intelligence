"""Compares Isolation Forest with Local Outlier Factor and One-Class SVM on labeled fault scenarios.

All models train on the same healthy baseline the production model uses and are scored on scenarios generated with
a different seed. Hyperparameters of the production model are chosen on a separate validation set, so the test
numbers are not tuned to themselves. Run `python -m app.evaluation` to print the report in Markdown.
"""
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_fscore_support, roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import RobustScaler
from sklearn.svm import OneClassSVM

from app import diagnosis, model_service, preprocessing, scenarios
from app.schemas import (AlgorithmMetrics, DiagnosisMetrics, EvaluationReport, SensitivityPoint,
                         TuningCandidate)

TEST_SEED = 7
VALIDATION_SEED = 11
PRODUCTION = "IsolationForest"
DATASET = ("Escenarios sintéticos etiquetados: redes sanas más cinco fallas simuladas (congestión, interferencia, "
           "cobertura débil, falla del proveedor y tráfico sospechoso) con intensidad aleatoria. No son datos "
           "reales; la evaluación se repetirá con mediciones del agente.")

TUNING_GRID = [
    {"n_estimators": n, "max_samples": samples}
    for samples in (256, 1024, 1.0)
    for n in (200, 500)
]
SENSITIVITY = (0.01, 0.02, 0.05, 0.10)


def candidates() -> dict:
    """The compared algorithms, all tuned to flag about the same share of healthy samples (2 %)."""
    contamination = model_service.CONTAMINATION
    return {
        PRODUCTION: model_service.build_model(),
        "LocalOutlierFactor": make_pipeline(
            RobustScaler(), LocalOutlierFactor(n_neighbors=35, contamination=contamination, novelty=True)),
        "OneClassSVM": make_pipeline(RobustScaler(), OneClassSVM(nu=contamination, gamma="scale")),
    }


def anomaly_scores(model, features: pd.DataFrame) -> np.ndarray:
    """Higher means more anomalous for every algorithm."""
    if hasattr(model, "score_samples"):
        return -model.score_samples(features)
    return -model.decision_function(features)


def _labels(frame: pd.DataFrame) -> np.ndarray:
    return (frame["scenario"] != scenarios.NORMAL).to_numpy()


def _round(value: float) -> float:
    return round(float(value), 4)


def _binary_metrics(truth: np.ndarray, flagged: np.ndarray) -> tuple[float, float, float, float]:
    precision, recall, f1, _ = precision_recall_fscore_support(truth, flagged, average="binary", zero_division=0)
    false_positive_rate = flagged[~truth].mean() if (~truth).any() else 0.0
    return precision, recall, f1, false_positive_rate


def score_algorithm(name: str, model, train: pd.DataFrame, test: pd.DataFrame) -> AlgorithmMetrics:
    features = preprocessing.transform(test)
    truth = _labels(test)
    start = time.perf_counter()
    model.fit(train)
    fitted = time.perf_counter()
    flagged = model.predict(features) == -1
    predicted = time.perf_counter()
    scores = anomaly_scores(model, features)
    precision, recall, f1, fpr = _binary_metrics(truth, flagged)
    by_type = {fault: _round(flagged[(test["scenario"] == fault).to_numpy()].mean()) for fault in scenarios.FAULT_TYPES}
    return AlgorithmMetrics(
        algorithm=name, precision=_round(precision), recall=_round(recall), f1=_round(f1),
        false_positive_rate=_round(fpr), roc_auc=_round(roc_auc_score(truth, scores)),
        average_precision=_round(average_precision_score(truth, scores)), recall_by_type=by_type,
        fit_ms=round((fitted - start) * 1000, 1),
        predict_us_per_sample=round((predicted - fitted) / len(test) * 1_000_000, 1),
        production=name == PRODUCTION,
    )


def tune(train: pd.DataFrame, validation: pd.DataFrame) -> list[TuningCandidate]:
    """Isolation Forest grid scored on the validation set; the best F1 (then fewest trees) is marked."""
    features = preprocessing.transform(validation)
    truth = _labels(validation)
    results = []
    for params in TUNING_GRID:
        model = model_service.build_model(**params).fit(train)
        precision, recall, f1, fpr = _binary_metrics(truth, model.predict(features) == -1)
        samples = params["max_samples"]
        results.append(TuningCandidate(n_estimators=params["n_estimators"],
                                       max_samples=f"todas ({len(train)})" if samples == 1.0 else str(samples),
                                       f1=_round(f1), recall=_round(recall), false_positive_rate=_round(fpr)))
    best = max(results, key=lambda c: (c.f1, -c.n_estimators))
    return [c.model_copy(update={"best": c is best}) for c in results]


def sensitivity(train: pd.DataFrame, test: pd.DataFrame) -> list[SensitivityPoint]:
    """How the production model trades recall for false alarms as the contamination changes."""
    features = preprocessing.transform(test)
    truth = _labels(test)
    points = []
    for contamination in SENSITIVITY:
        model = model_service.build_model(contamination=contamination).fit(train)
        precision, recall, _, fpr = _binary_metrics(truth, model.predict(features) == -1)
        points.append(SensitivityPoint(contamination=contamination, precision=_round(precision),
                                       recall=_round(recall), false_positive_rate=_round(fpr),
                                       production=contamination == model_service.CONTAMINATION))
    return points


def evaluate_diagnosis(service: model_service.AnomalyDetectionService, test: pd.DataFrame) -> DiagnosisMetrics:
    """Accuracy of the probable cause on the faults the production model detects."""
    features = preprocessing.transform(test)
    detected = service.flag(features)
    confusion: dict[str, dict[str, int]] = {fault: {} for fault in scenarios.FAULT_TYPES}
    hits = total = 0
    for position, (_, row) in enumerate(features.iterrows()):
        actual = test["scenario"].iat[position]
        if actual == scenarios.NORMAL or not detected[position]:
            continue
        predicted = diagnosis.diagnose(service.deviations(row)).value
        confusion[actual][predicted] = confusion[actual].get(predicted, 0) + 1
        hits += predicted == actual
        total += 1
    return DiagnosisMetrics(accuracy=_round(hits / total) if total else 0.0, evaluated=total, confusion=confusion)


def evaluate(normal: int = 2000, per_fault: int = 100) -> EvaluationReport:
    baseline = model_service.generate_baseline()
    train = preprocessing.transform(baseline)
    test = scenarios.generate(normal, per_fault, seed=TEST_SEED)
    validation = scenarios.generate(normal, per_fault, seed=VALIDATION_SEED)
    algorithms = [score_algorithm(name, model, train, test) for name, model in candidates().items()]
    service = model_service.AnomalyDetectionService.train(baseline)
    return EvaluationReport(
        dataset=DATASET, train_samples=len(baseline), test_normal=normal,
        test_anomalies=per_fault * len(scenarios.FAULT_TYPES), production_algorithm=PRODUCTION,
        model_version=model_service.MODEL_VERSION, algorithms=algorithms, tuning=tune(train, validation),
        sensitivity=sensitivity(train, test), diagnosis=evaluate_diagnosis(service, test),
        generated_at=datetime.now(timezone.utc),
    )


def to_markdown(report: EvaluationReport) -> str:
    pct = lambda value: f"{value * 100:.1f} %"
    lines = [
        f"# Evaluación de modelos ({report.model_version})", "",
        report.dataset, "",
        f"Entrenamiento: {report.train_samples} mediciones sanas. Prueba: {report.test_normal} sanas y "
        f"{report.test_anomalies} con falla.", "",
        "## Comparación de algoritmos", "",
        "| Algoritmo | Precisión | Recall | F1 | Falsos positivos | ROC-AUC | Entrenar | Predecir/medición |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for a in report.algorithms:
        name = f"**{a.algorithm}** (producción)" if a.production else a.algorithm
        lines.append(f"| {name} | {pct(a.precision)} | {pct(a.recall)} | {a.f1:.3f} | {pct(a.false_positive_rate)} | "
                     f"{a.roc_auc:.3f} | {a.fit_ms:.0f} ms | {a.predict_us_per_sample:.1f} µs |")
    lines += ["", "## Recall por tipo de falla", "",
              "| Algoritmo | " + " | ".join(scenarios.FAULT_TYPES) + " |",
              "|---|" + "---|" * len(scenarios.FAULT_TYPES)]
    for a in report.algorithms:
        lines.append(f"| {a.algorithm} | " + " | ".join(pct(a.recall_by_type[f]) for f in scenarios.FAULT_TYPES) + " |")
    lines += ["", "## Ajuste de Isolation Forest (conjunto de validación)", "",
              "| Árboles | Muestras por árbol | F1 | Recall | Falsos positivos |", "|---|---|---|---|---|"]
    for c in report.tuning:
        mark = " ✔" if c.best else ""
        lines.append(f"| {c.n_estimators} | {c.max_samples} | {c.f1:.3f}{mark} | {pct(c.recall)} | "
                     f"{pct(c.false_positive_rate)} |")
    lines += ["", "## Sensibilidad del umbral (contaminación)", "",
              "| Contaminación | Precisión | Recall | Falsos positivos |", "|---|---|---|---|"]
    for p in report.sensitivity:
        mark = " (producción)" if p.production else ""
        lines.append(f"| {p.contamination:.2f}{mark} | {pct(p.precision)} | {pct(p.recall)} | "
                     f"{pct(p.false_positive_rate)} |")
    lines += ["", "## Diagnóstico de la causa", "",
              f"Acierto: {pct(report.diagnosis.accuracy)} sobre {report.diagnosis.evaluated} fallas detectadas.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    print(to_markdown(evaluate()))
