"""Optional FastAPI transport over the application services.

This layer is a thin adapter and lives in an *optional* dependency group. A CLI-only
install never imports it, so FastAPI is never a prerequisite for local use.

Security posture (API_CONTRACTS.md section 7):

* No general-purpose command-execution endpoint exists. Every route maps to a named
  application service.
* Write-enabled routes require bearer authentication. There is deliberately no
  "unauthenticated but convenient" mode.
* Responses are redacted before leaving the process.
"""

from __future__ import annotations

import hmac
import os
from typing import Annotated, Any

from pydantic import BaseModel, Field

from ..application import Services

#: Routes that change state. These require authentication.
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

AUTH_ENV_VAR = "OPENMEDIC_API_TOKEN"


class _ApiState(BaseModel):
    """Holds the shared service graph for the app lifetime."""

    model_config = {"arbitrary_types_allowed": True}

    services: Any = Field(default=None)


def create_app(services: Services | None = None) -> Any:
    """Build the FastAPI application.

    Imported lazily inside this function on purpose: a CLI-only install must be able to
    import ``openmedic`` without FastAPI present.
    """
    from fastapi import Depends, FastAPI, Header, HTTPException, Request

    from ..domain.errors import OpenMedicError

    app = FastAPI(
        title="OpenMedic",
        version=_openmedic_version(),
        description=(
            "Read-mostly API over the OpenMedic incident store. "
            "Write-enabled routes require bearer authentication."
        ),
    )

    state = _ApiState(services=services or Services.default())

    def require_auth(
        request: Request, authorization: Annotated[str | None, Header()] = None
    ) -> None:
        """Enforce bearer auth on any state-changing request.

        A missing token on the server is a configuration error and fails closed: writes
        are rejected rather than silently permitted.
        """
        if request.method not in WRITE_METHODS:
            return
        expected = os.environ.get(AUTH_ENV_VAR)
        if not expected:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"write access is disabled: set {AUTH_ENV_VAR} to enable "
                    "authenticated write routes"
                ),
            )
        supplied = (authorization or "").removeprefix("Bearer ").strip()
        if not supplied or not hmac.compare_digest(supplied, expected):
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "version": _openmedic_version()}

    @app.get("/api/v1/incidents", dependencies=[Depends(require_auth)])
    def list_incidents(state_filter: str | None = None, limit: int = 50) -> dict[str, object]:
        records = state.services.list_incidents(state=state_filter, limit=limit)
        return {
            "count": len(records),
            "incidents": state.services.incident_payloads(records),
        }

    @app.post("/api/v1/incidents", dependencies=[Depends(require_auth)])
    def create_incident(payload: dict[str, Any]) -> dict[str, object]:
        import json

        record = state.services.ingest_event_json(json.dumps(payload))
        return {"incident_id": record.incident_id, "state": record.state.value}

    @app.get("/api/v1/incidents/{incident_id}", dependencies=[Depends(require_auth)])
    def get_incident(incident_id: str) -> dict[str, object]:
        record = state.services.get_incident(incident_id)
        return state.services.incident_payloads([record])[0]

    @app.post("/api/v1/incidents/{incident_id}/diagnose", dependencies=[Depends(require_auth)])
    def diagnose_incident(incident_id: str) -> dict[str, object]:
        record = state.services.diagnose_stored(incident_id)
        return {"incident_id": record.incident_id, "state": record.state.value}

    @app.post("/api/v1/incidents/{incident_id}/validate", dependencies=[Depends(require_auth)])
    def validate_incident(incident_id: str) -> dict[str, object]:
        outcome = state.services.validate(incident_id)
        return outcome.payload

    @app.get("/api/v1/providers", dependencies=[Depends(require_auth)])
    def providers() -> dict[str, object]:
        return state.services.provider_payload()

    @app.exception_handler(OpenMedicError)
    async def _domain_error_handler(request: Request, exc: OpenMedicError) -> Any:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=_http_status(exc.exit_code), content=exc.to_dict())

    return app


def _http_status(exit_code: int) -> int:
    """Map documented CLI exit codes to HTTP statuses.

    Keeping the mapping in one place means the CLI and the API never disagree about what
    "validation failed" means.
    """
    return {
        3: 400,  # invalid input
        4: 422,  # validation failed
        5: 502,  # integration unavailable
        6: 409,  # unresolved repair
        7: 409,  # human review required
        2: 400,  # usage
    }.get(exit_code, 400)


def _openmedic_version() -> str:
    from .. import __version__

    return __version__


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the API with uvicorn. Only reachable through the ``api`` extra."""
    import uvicorn

    uvicorn.run(create_app(), host=host, port=port)  # pragma: no cover - runtime


def main() -> None:  # pragma: no cover - console script
    """Run the API entry point for the ``openmedic-api`` console script."""
    import typer

    typer.run(serve)


__all__ = ["create_app", "main", "serve"]
