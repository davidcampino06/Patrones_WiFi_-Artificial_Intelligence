import pytest

from app.main import require_api_key


def test_in_railway_the_service_refuses_to_start_without_a_key():
    with pytest.raises(RuntimeError, match="AI_API_KEY no está configurada"):
        require_api_key({"RAILWAY_ENVIRONMENT_NAME": "production"}, api_key=None)
    with pytest.raises(RuntimeError):
        require_api_key({"RAILWAY_PROJECT_ID": "abc"}, api_key="")


def test_with_a_key_or_locally_it_starts():
    require_api_key({"RAILWAY_ENVIRONMENT_NAME": "production"}, api_key="una-clave-larga")
    require_api_key({}, api_key=None)  # local development without configuration


def test_an_open_service_in_railway_must_be_asked_for_explicitly():
    require_api_key({"RAILWAY_ENVIRONMENT": "production", "AI_ALLOW_NO_KEY": "true"}, api_key=None)
    with pytest.raises(RuntimeError):
        require_api_key({"RAILWAY_ENVIRONMENT": "production", "AI_ALLOW_NO_KEY": "yes"}, api_key=None)
