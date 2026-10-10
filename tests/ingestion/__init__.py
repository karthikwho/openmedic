"""Ingestion test package marker.

The package is importable as ``tests.ingestion`` only from the repository root, so
the test modules in here stay self-contained: each one derives the fixture path
from ``__file__`` and imports the public API from ``openmedic.ingestion``.
"""

from __future__ import annotations

__all__: list[str] = []
