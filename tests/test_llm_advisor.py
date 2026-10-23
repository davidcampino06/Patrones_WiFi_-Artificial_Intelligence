from types import SimpleNamespace

import pytest

from app.llm_advisor import ClaudeAdvisor, RuleAdvisor, build_prompt
from app.model_service import AnomalyDetectionService, generate_baseline
from app.schemas import AnalysisRequest
from tests.conftest import DEGRADED, NORMAL


class FakeMessages:
    def __init__(self, text=None, error=None):
        self.text, self.error, self.calls = text, error, []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=self.text)])


@pytest.fixture(scope="module")
def detection():
    service = AnomalyDetectionService.train(generate_baseline())
    request = AnalysisRequest(network_id=1, simulated_data=True, measurements=[NORMAL, DEGRADED])
    return service.detect(request), request


def advisor_with(messages):
    return ClaudeAdvisor(SimpleNamespace(messages=messages), model="test-model")


def test_claude_recommendation_replaces_rules(detection):
    result, request = detection
    messages = FakeMessages(text="1. Cambia el canal.\n2. Revisa el AP.")

    enriched = advisor_with(messages).enrich(result, request)

    assert enriched.recommendation_source == "CLAUDE"
    assert enriched.recommendation.startswith("1. Cambia el canal.")
    assert messages.calls[0]["model"] == "test-model"


def test_api_failure_keeps_rule_recommendation(detection):
    result, request = detection

    enriched = advisor_with(FakeMessages(error=RuntimeError("quota exceeded"))).enrich(result, request)

    assert enriched.recommendation_source == "RULES"
    assert enriched.recommendation == result.recommendation


def test_prompt_contains_metrics_but_no_identifiers(detection):
    result, request = detection

    prompt = build_prompt(result, request)

    assert "pérdida de paquetes" in prompt
    assert "Datos simulados: sí" in prompt
    assert "networkId" not in prompt and "mac" not in prompt.lower()


def test_long_answers_are_truncated(detection):
    result, request = detection

    enriched = advisor_with(FakeMessages(text="x" * 5000)).enrich(result, request)

    assert len(enriched.recommendation) == 1500


def test_without_api_key_the_rules_advise_and_keep_the_result(monkeypatch, detection):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result, request = detection

    advisor = ClaudeAdvisor.from_env()

    assert isinstance(advisor, RuleAdvisor)
    assert advisor.model == "reglas"
    assert advisor.enrich(result, request) is result
    assert result.recommendation_source == "RULES"


def test_prompt_includes_the_probable_cause(detection):
    prompt = build_prompt(*detection)

    assert "Causa probable según el diagnóstico: cobertura débil" in prompt
