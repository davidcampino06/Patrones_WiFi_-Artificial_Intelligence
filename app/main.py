import logging
import math
import os
import secrets
import threading
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import channel, evaluation, nearby, quality, security, training
from app.llm_advisor import Advisor, ClaudeAdvisor
from app.model_service import AnomalyDetectionService
from app.schemas import (AnalysisRequest, AnalysisResponse, EvaluationReport, ModelInfo, TrainingRequest,
                         TrainingResult)
from app.schemas_channel import ChannelRequest, ChannelResponse
from app.schemas_findings import FindingsResponse
from app.schemas_nearby import NearbyRequest
from app.schemas_quality import QualityRequest, QualityResponse
from app.schemas_security import SecurityRequest, SecurityResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s - %(message)s")

MODEL_PATH = os.getenv("AI_MODEL_PATH", "models/anomaly_model.joblib")
API_KEY = os.getenv("AI_API_KEY")
logger = logging.getLogger(__name__)


class EvaluationRun:
    """Runs the model comparison once in the background so startup and detection are never delayed."""

    def __init__(self):
        self.report: EvaluationReport | None = None
        self.failed = False
        self._done = threading.Event()

    def start(self) -> "EvaluationRun":
        threading.Thread(target=self._run, name="model-evaluation", daemon=True).start()
        return self

    def wait(self, timeout: float) -> bool:
        return self._done.wait(timeout)

    def _run(self) -> None:
        try:
            self.report = evaluation.evaluate()
            logger.info("Model evaluation ready")
        except Exception:  # the comparison is informative; detection keeps working without it
            logger.exception("Model evaluation failed")
            self.failed = True
        finally:
            self._done.set()


RAILWAY_VARIABLES = ("RAILWAY_ENVIRONMENT", "RAILWAY_ENVIRONMENT_NAME", "RAILWAY_PROJECT_ID")


def require_api_key(environ=os.environ, api_key: str | None = None) -> None:
    """In Railway the service must never run open: without AI_API_KEY anyone who reaches it could use (and retrain) the
    model. Locally the key stays optional so the service can be tried without configuration. AI_ALLOW_NO_KEY=true is
    an explicit, visible exception for a demonstration."""
    on_railway = any(environ.get(name) for name in RAILWAY_VARIABLES)
    if on_railway and not api_key and environ.get("AI_ALLOW_NO_KEY") != "true":
        raise RuntimeError("AI_API_KEY no está configurada: en Railway el servicio de IA no arranca sin clave. Ponle la "
                           "misma clave que tiene el backend en su variable AI_API_KEY.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    require_api_key(api_key=API_KEY)
    app.state.detector = AnomalyDetectionService.load_or_train(MODEL_PATH)
    app.state.advisor = ClaudeAdvisor.from_env()
    app.state.evaluation = EvaluationRun().start()
    yield


app = FastAPI(title="WiFiSense AI", version="1.3.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

# The biggest legitimate body is a training of 20 000 measurements (about 4 MB). Anything larger is refused before it is
# read, so a client cannot make the service hold an unbounded request in memory.
MAX_BODY_BYTES = 8 * 1024 * 1024


class BodyLimit:
    """ASGI middleware: 413 when the declared size, or the bytes actually received, pass MAX_BODY_BYTES."""

    def __init__(self, app, limit: int = MAX_BODY_BYTES):
        self.app = app
        self.limit = limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.limit:
            return await self._too_large(send)
        received = 0

        async def counted():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.limit:
                    raise BodyTooLarge()
            return message

        try:
            await self.app(scope, counted, send)
        except BodyTooLarge:
            await self._too_large(send)

    @staticmethod
    async def _too_large(send):
        body = b'{"detail":"La solicitud es demasiado grande."}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


class BodyTooLarge(Exception):
    pass


app.add_middleware(BodyLimit)


def _json_safe(value):
    """NaN and infinity are not JSON: as text, so a validation error can always be written."""
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, error: RequestValidationError) -> JSONResponse:
    """422 with the list of errors, as FastAPI does. A NaN or an infinity in the body (JSON allows writing them, and
    Jackson writes NaN as the text "NaN") used to end in a 500, because the default answer repeats the invalid value
    and NaN cannot be written as JSON."""
    return JSONResponse(status_code=422, content={"detail": _json_safe(jsonable_encoder(error.errors()))})


def verify_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Only the backend calls this service; the shared key is optional for local development."""
    if API_KEY and not secrets.compare_digest(x_api_key or "", API_KEY):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")


def detector(request: Request) -> AnomalyDetectionService:
    return request.app.state.detector


def advisor(request: Request) -> Advisor:
    return request.app.state.advisor


@app.get("/health")
def health() -> dict:
    return {"status": "UP"}


@app.get("/api/v1/model", response_model=ModelInfo, response_model_by_alias=True,
         dependencies=[Depends(verify_api_key)])
def model_info(service: AnomalyDetectionService = Depends(detector),
               advice: Advisor = Depends(advisor)) -> ModelInfo:
    return service.info(advice.model)


_training_lock = threading.Lock()


@app.post("/api/v1/model/train", response_model=TrainingResult, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def train_model(payload: TrainingRequest, request: Request) -> TrainingResult:
    """Trains a model with real measurements sent by the backend and puts it in use only if it is better (or rebuilds
    the one already promoted, after a restart). Detection keeps using the current model meanwhile."""
    with _training_lock:
        try:
            result, model = training.train(payload, request.app.state.detector)
        except training.NotEnoughData as error:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(error))
        if model is not None:
            request.app.state.detector = model
            try:
                model.save(MODEL_PATH)
            except OSError:
                logger.warning("The new model is in use but could not be saved to %s", MODEL_PATH)
            logger.info("Model %s in use (%s)", model.version, result.decision)
        return result


@app.get("/api/v1/model/evaluation", response_model=EvaluationReport, response_model_by_alias=True,
         dependencies=[Depends(verify_api_key)])
def model_evaluation(request: Request) -> EvaluationReport:
    run: EvaluationRun = request.app.state.evaluation
    if run.report is None:
        detail = ("La evaluación del modelo no está disponible." if run.failed
                  else "La evaluación del modelo está en curso. Intenta de nuevo en unos segundos.")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=detail)
    return run.report


@app.post("/api/v1/anomalies/detect", response_model=AnalysisResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def detect_anomalies(payload: AnalysisRequest,
                     service: AnomalyDetectionService = Depends(detector),
                     advice: Advisor = Depends(advisor)) -> AnalysisResponse:
    result = service.detect(payload)
    # Claude is only asked when there is something to explain: the agent reports every few minutes and a normal
    # result already has nothing to recommend, so this keeps the API cost (and latency) proportional to problems.
    return advice.enrich(result, payload) if result.anomaly_detected else result


@app.post("/api/v1/quality/score", response_model=QualityResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def quality_score(payload: QualityRequest) -> QualityResponse:
    """0-100 quality of one connection test or measurement, with what it is good for and what to improve."""
    return quality.score(payload)


@app.post("/api/v1/security/assess", response_model=SecurityResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def security_assess(payload: SecurityRequest) -> SecurityResponse:
    """0-100 security audit of a home network from what the agent saw: encryption, router ports, new devices."""
    return security.assess(payload)


@app.post("/api/v1/channel/recommend", response_model=ChannelResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def channel_recommend(payload: ChannelRequest) -> ChannelResponse:
    """Channel with the least interference from the neighbouring networks the agent saw, and whether to move to it."""
    return channel.recommend(payload)


@app.post("/api/v1/nearby/analyze", response_model=FindingsResponse, response_model_by_alias=True,
          dependencies=[Depends(verify_api_key)])
def nearby_analyze(payload: NearbyRequest) -> FindingsResponse:
    """Facts and inferences of one scan of the nearby Wi-Fi networks: crowded channels, weak security and networks
    that look like the user's own."""
    return nearby.analyze(payload)
