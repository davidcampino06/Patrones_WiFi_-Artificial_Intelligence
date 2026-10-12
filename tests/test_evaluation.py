import pytest

from app import evaluation, model_service, scenarios


@pytest.fixture(scope="module")
def report():
    return evaluation.evaluate(normal=400, per_fault=40)


def test_report_compares_the_three_algorithms_on_the_same_data(report):
    assert [a.algorithm for a in report.algorithms] == ["IsolationForest", "LocalOutlierFactor", "OneClassSVM"]
    assert report.test_anomalies == 40 * len(scenarios.FAULT_TYPES)
    for algorithm in report.algorithms:
        assert 0 <= algorithm.precision <= 1 and 0 <= algorithm.recall <= 1
        assert set(algorithm.recall_by_type) == set(scenarios.FAULT_TYPES)
        assert algorithm.roc_auc > 0.9


def test_production_model_keeps_false_alarms_low(report):
    production = next(a for a in report.algorithms if a.production)

    assert production.algorithm == "IsolationForest"
    assert production.false_positive_rate < 0.05


def test_tuning_picks_one_candidate_from_validation_data(report):
    assert sum(c.best for c in report.tuning) == 1
    assert len(report.tuning) == len(evaluation.TUNING_GRID)


def test_more_contamination_means_more_recall_and_more_false_alarms(report):
    recalls = [p.recall for p in report.sensitivity]
    alarms = [p.false_positive_rate for p in report.sensitivity]

    assert recalls == sorted(recalls)
    assert alarms == sorted(alarms)
    assert [p.contamination for p in report.sensitivity if p.production] == [model_service.CONTAMINATION]


def test_diagnosis_is_mostly_right_on_detected_faults(report):
    assert report.diagnosis.evaluated > 0
    assert report.diagnosis.accuracy > 0.8


def test_markdown_report_is_in_spanish(report):
    text = evaluation.to_markdown(report)

    assert "## Comparación de algoritmos" in text
    assert "(producción)" in text
