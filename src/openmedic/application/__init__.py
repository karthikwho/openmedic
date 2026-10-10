"""Application services: use-case orchestration shared by the CLI and the API.

The CLI and the (optional) API are thin transports. Everything that decides what happens
lives here, so both interfaces necessarily behave identically.
"""

from __future__ import annotations

from .services import Services

__all__ = ["Services"]
