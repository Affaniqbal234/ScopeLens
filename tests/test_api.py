from typing import cast

import pytest
from fastapi.testclient import TestClient

from scopelens.api.app import create_app
from scopelens.cli import main
from scopelens.config import ProjectConfig
from scopelens.orchestration.store import OrchestrationStore
from scopelens.orchestration.worker import AssessmentWorker

TOKEN = "test-local-token-0123456789abcdef"


def project() -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "project": {
                "id": "api-lab",
                "name": "API lab",
                "scope": {
                    "web_targets": [
                        {
                            "origin": "https://app.local",
                            "approved_addresses": ["127.0.0.1"],
                        }
                    ]
                },
            },
            "profiles": [{"id": "safe"}],
        }
    )


def client(*, origins: tuple[str, ...] = ()) -> TestClient:
    app = create_app(
        project(),
        cast(OrchestrationStore, object()),
        cast(AssessmentWorker, object()),
        token=TOKEN,
        allowed_origins=origins,
    )
    return TestClient(app, raise_server_exceptions=False)


def authorization() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}"}


def test_health_is_shallow_and_does_not_require_authentication() -> None:
    response = client().get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize(
    "headers,query",
    [({}, ""), ({"Authorization": "Bearer wrong"}, ""), ({}, f"?token={TOKEN}")],
)
def test_operational_endpoints_require_header_token(
    headers: dict[str, str], query: str
) -> None:
    response = client().get(f"/api/v1/project{query}", headers=headers)
    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "authentication_required",
            "message": "authentication required",
        }
    }
    assert TOKEN not in response.text


def test_project_summary_comes_from_server_configuration() -> None:
    response = client().get("/api/v1/project", headers=authorization())
    assert response.status_code == 200
    assert response.json()["project"]["id"] == "api-lab"
    assert response.json()["project"]["scope"]["web_targets"] == [
        {
            "origin": "https://app.local",
            "approved_addresses": ["127.0.0.1"],
        }
    ]
    assert TOKEN not in response.text


def test_cors_allows_only_configured_local_origin() -> None:
    api = client(origins=("http://localhost:5173",))
    allowed = api.options(
        "/api/v1/project",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    denied = api.options(
        "/api/v1/project",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert denied.status_code == 400
    assert "access-control-allow-origin" not in denied.headers


def test_nonlocal_or_duplicate_cors_origins_are_rejected() -> None:
    with pytest.raises(ValueError, match="localhost"):
        client(origins=("https://example.com",))
    with pytest.raises(ValueError, match="duplicate"):
        client(origins=("http://localhost:5173", "http://localhost:5173"))


def test_openapi_exposes_bearer_auth_and_bounded_retest_fields() -> None:
    schema = client().get("/openapi.json").json()
    security = schema["components"]["securitySchemes"]
    fields = schema["components"]["schemas"]["FocusedRetestRequest"]["properties"]
    assert security["HTTPBearer"]["scheme"] == "bearer"
    assert set(fields) == {
        "assessment_id",
        "project_id",
        "profile_id",
        "origin",
        "approved_address",
    }
    assert not {"path", "method", "flags", "template"} & set(fields)


def test_api_cli_requires_explicit_container_bind(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["api-serve", "--help"])
    assert stopped.value.code == 0
    output = capsys.readouterr().out
    assert "--cors-origin" in output
    assert "--host" not in output
    assert "--container-bind" in output


def test_internal_errors_do_not_echo_exception_details() -> None:
    class FailingStore:
        def list_manifests(self, project_id: str) -> list[object]:
            raise RuntimeError(f"secret for {project_id} at /private/history")

    app = create_app(
        project(),
        cast(OrchestrationStore, FailingStore()),
        cast(AssessmentWorker, object()),
        token=TOKEN,
    )
    response = TestClient(app, raise_server_exceptions=False).get(
        "/api/v1/assessments?project_id=api-lab", headers=authorization()
    )
    assert response.status_code == 500
    assert response.json() == {
        "error": {"code": "internal_error", "message": "internal server error"}
    }
    assert "secret" not in response.text
    assert "/private/history" not in response.text
