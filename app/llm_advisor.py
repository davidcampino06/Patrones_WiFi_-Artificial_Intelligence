import logging
import os
import statistics
from typing import Protocol

import anthropic

from app.diagnosis import LABELS
from app.model_service import FEATURE_LABELS
from app.preprocessing import FEATURES
from app.schemas import AnalysisRequest, AnalysisResponse

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
MAX_RECOMMENDATION_CHARS = 1500

SYSTEM_PROMPT = (
    "Eres un ingeniero experto en redes Wi-Fi que apoya al equipo de TI de una universidad. "
    "Recibes métricas de una red, el veredicto de un modelo Isolation Forest y la causa probable que indican "
    "las reglas de diagnóstico; si los datos contradicen esa causa, dilo. "
    "Responde en español, en texto plano sin markdown, con máximo 3 recomendaciones concretas y numeradas "
    "(una línea cada una), basadas solo en los datos recibidos. "
    "Si la red está normal, sugiere qué vigilar. Si los datos son simulados, menciónalo en una frase final."
)


class Advisor(Protocol):
    """Who writes the recommendation of a detected anomaly: the rules (always) or Claude (optional)."""

    @property
    def model(self) -> str: ...

    def enrich(self, result: AnalysisResponse, request: AnalysisRequest) -> AnalysisResponse: ...


class RuleAdvisor:
    """<b>Null Object</b> of the advisor: without ANTHROPIC_API_KEY the recommendation written by the rules of the
    diagnosis is kept as it is. The endpoints always have an advisor, so they never ask "is there one?", and that the
    rules are the default (and the source when Claude fails) is explicit here instead of being a missing value."""

    model = "reglas"

    def enrich(self, result: AnalysisResponse, request: AnalysisRequest) -> AnalysisResponse:
        return result


class ClaudeAdvisor:
    """Optional generative recommendations. Only aggregated metrics are sent: no IPs, MACs or user data."""

    def __init__(self, client, model: str = DEFAULT_MODEL):
        self._client = client
        self._model = model

    @property
    def model(self) -> str:
        return self._model

    @classmethod
    def from_env(cls) -> "Advisor":
        """Claude when ANTHROPIC_API_KEY is set; otherwise the rules (the Null Object, never None)."""
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            logger.info("ANTHROPIC_API_KEY not set: using rule-based recommendations")
            return RuleAdvisor()
        client = anthropic.Anthropic(api_key=api_key, timeout=20.0, max_retries=1)
        return cls(client, os.getenv("CLAUDE_MODEL", DEFAULT_MODEL))

    def enrich(self, result: AnalysisResponse, request: AnalysisRequest) -> AnalysisResponse:
        """Replaces the rule recommendation with Claude's; on any failure the rule result is kept."""
        try:
            text = self._ask(build_prompt(result, request))
        except Exception as error:  # network, quota or API errors must never break the analysis
            logger.warning("Claude recommendation unavailable: %s", error)
            return result
        if not text:
            return result
        return result.model_copy(update={"recommendation": text[:MAX_RECOMMENDATION_CHARS],
                                         "recommendation_source": "CLAUDE"})

    def _ask(self, prompt: str) -> str:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=400,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(block.text for block in response.content if block.type == "text").strip()


def build_prompt(result: AnalysisResponse, request: AnalysisRequest) -> str:
    latest = request.measurements[-1]
    lines = ["Métricas de la red (último valor | mediana de la ventana):"]
    for feature in FEATURES:
        values = [getattr(m, feature) for m in request.measurements if getattr(m, feature) is not None]
        if values:
            current = getattr(latest, feature)
            current_text = "sin dato" if current is None else f"{current:g}"
            lines.append(f"- {FEATURE_LABELS[feature]}: {current_text} | {statistics.median(values):g}")
    contributors = ", ".join(FEATURE_LABELS[f] for f in result.contributing_features) or "ninguna"
    lines += [
        f"Mediciones analizadas: {result.sample_size}",
        f"Anomalía detectada: {'sí' if result.anomaly_detected else 'no'}",
        f"Puntaje de anomalía (0-1): {result.anomaly_score}",
        f"Severidad: {result.severity.value}",
        f"Causa probable según el diagnóstico: {LABELS[result.anomaly_type]}",
        f"Variables que más se desvían: {contributors}",
        f"Datos simulados: {'sí' if request.simulated_data else 'no'}",
    ]
    return "\n".join(lines)
