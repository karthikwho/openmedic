"""OpenMedic — local-first CI/CD failure diagnosis and safe recovery.

The single source of truth for the package version is ``pyproject.toml``. This module
derives the runtime value from installed distribution metadata so there is never a
second, drifting copy of the version number.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__", "get_version"]

_DISTRIBUTION = "openmedic"


def get_version() -> str:
    """Return the installed distribution version, or a clearly-marked fallback.

    The fallback is only reachable when running from a source checkout that has not
    been installed. It is deliberately distinct from any released number so it cannot
    be mistaken for one.
    """
    try:
        return version(_DISTRIBUTION)
    except PackageNotFoundError:  # pragma: no cover - only when not installed
        return "0.0.0+unknown"


__version__: str = get_version()
