FROM public.ecr.aws/docker/library/python:3.13-slim

WORKDIR /service
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AI_MODEL_PATH=/service/models/anomaly_model.joblib

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
RUN python -c "from app.model_service import AnomalyDetectionService as s; s.load_or_train('/service/models/anomaly_model.joblib')"

RUN useradd --create-home appuser && chown -R appuser /service
USER appuser

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
