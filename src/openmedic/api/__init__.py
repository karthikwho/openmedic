"""Optional API/UI layer. Requires the ``api`` extra (FastAPI + uvicorn)."""

from __future__ import annotations

from .app import create_app, main, serve

__all__ = ["create_app", "main", "serve"]
