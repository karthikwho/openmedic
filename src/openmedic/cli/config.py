"""Application configuration.

Resolution order, highest priority first:

1. Command-line flags.
2. Environment variables (``OPENMEDIC_*``).
3. A project config file: ``.openmedic.toml`` in the current directory, then
   ``~/.config/openmedic/config.toml``.
4. Documented defaults.

Credentials are **never** read from config files. Only environment variables are
consulted for secrets, and only the *name* of the env var holding a key ever appears in
a config object (see :class:`ProviderConfig.api_key_env`), so a serialized config cannot
leak a credential.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Final

from ..domain.errors import InvalidInputError, UsageError

DEFAULT_DB_FILENAME: Final = "data/openmedic.db"

#: Config file names searched in order.
CONFIG_FILENAMES: Final = (".openmedic.toml", "openmedic.toml")

CONFIG_ENV_PREFIX: Final = "OPENMEDIC_"


@dataclass(slots=True)
class ProviderSettings:
    """Model provider settings. All optional; absence is the normal state."""

    name: str = "none"
    endpoint: str = ""
    model: str = ""
    api_key_env: str = ""
    timeout_seconds: float = 30.0
    max_retries: int = 0
    temperature: float = 0.0
    max_context_chars: int = 6000
    enabled: bool = False


@dataclass(slots=True)
class AppConfig:
    """Everything the CLI needs to run, resolved and validated."""

    database_path: Path = Path(DEFAULT_DB_FILENAME)
    log_level: str = "WARNING"
    color: bool = True
    json_output: bool = False
    prefer_docker: bool = True
    dry_run_by_default: bool = True
    max_files_changed: int = 5
    require_review_above: str = "medium"
    check_timeout_seconds: float = 300.0
    provider: ProviderSettings = field(default_factory=ProviderSettings)
    source: str = "defaults"

    @property
    def database_dir(self) -> Path:
        """Return the directory that holds the local database."""
        return self.database_path.parent

    def with_overrides(self, **overrides: object) -> AppConfig:
        """Return a copy with the given fields replaced (``None`` is ignored)."""
        cleaned = {k: v for k, v in overrides.items() if v is not None}
        if not cleaned:
            return self
        return replace(self, **cleaned)  # type: ignore[arg-type]


def config_search_paths(start: Path | None = None) -> list[Path]:
    """Return candidate config paths in priority order."""
    base = start or Path.cwd()
    paths = [base / name for name in CONFIG_FILENAMES]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    home_cfg = (
        Path(xdg) / "openmedic" / "config.toml"
        if xdg
        else Path.home() / ".config" / "openmedic" / "config.toml"
    )
    paths.append(home_cfg)
    return paths


def _validate_log_level(value: object) -> str:
    allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    text = str(value).upper()
    if text not in allowed:
        msg = f"invalid log level {value!r}; expected one of {sorted(allowed)}"
        raise InvalidInputError(msg)
    return text


def load_config(path: Path | None = None, *, env: dict[str, str] | None = None) -> AppConfig:
    """Load configuration from disk and environment.

    Unknown keys in a config file are an error rather than being silently ignored: a
    misspelled key that silently does nothing is how misconfiguration survives.
    """
    environ = os.environ if env is None else env

    config = AppConfig()

    search = [path] if path is not None else config_search_paths()
    for candidate in search:
        if candidate is None or not candidate.is_file():
            continue
        data = _read_toml(candidate)
        config = _apply_mapping(config, data, source=str(candidate))
        break

    config = _apply_env(config, environ)
    config.log_level = _validate_log_level(config.log_level)
    return config


def _read_toml(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        msg = f"could not parse config file {path}: {exc}"
        raise InvalidInputError(msg) from exc
    except OSError as exc:  # pragma: no cover - unreadable file
        msg = f"could not read config file {path}"
        raise InvalidInputError(msg, detail=str(exc)) from exc
    if not isinstance(data, dict):
        msg = f"config file {path} must contain a TOML table"
        raise InvalidInputError(msg)
    return data


_KNOWN_SCALARS: Final = frozenset(
    {
        "database_path",
        "log_level",
        "color",
        "json_output",
        "prefer_docker",
        "dry_run_by_default",
        "max_files_changed",
        "require_review_above",
        "check_timeout_seconds",
    }
)


def _apply_mapping(config: AppConfig, data: dict[str, object], *, source: str) -> AppConfig:
    # Support both `[openmedic]`-scoped and bare top-level keys. `[openmedic.provider]`
    # becomes `{"openmedic": {"provider": {...}}}`, so unwrap when the top level holds
    # no recognised keys of its own.
    if not (set(data) & (_KNOWN_SCALARS | {"provider"})):
        inner = data.get("openmedic")
        if isinstance(inner, dict):
            data = dict(inner)

    scalar_keys = {k: v for k, v in data.items() if k in _KNOWN_SCALARS}
    unknown = set(data) - _KNOWN_SCALARS - {"provider"}
    if unknown:
        msg = f"unknown config key(s) in {source}: {sorted(unknown)}"
        raise InvalidInputError(msg)

    result = config
    if "database_path" in scalar_keys:
        result.database_path = Path(str(scalar_keys["database_path"]))
    if "log_level" in scalar_keys:
        result.log_level = _validate_log_level(scalar_keys["log_level"])
    for key in ("color", "json_output", "prefer_docker", "dry_run_by_default"):
        if key in scalar_keys:
            setattr(result, key, bool(scalar_keys[key]))
    for key in ("max_files_changed",):
        if key in scalar_keys:
            result.max_files_changed = int(scalar_keys[key])  # type: ignore[arg-type]
    if "require_review_above" in scalar_keys:
        result.require_review_above = str(scalar_keys["require_review_above"])
    if "check_timeout_seconds" in scalar_keys:
        result.check_timeout_seconds = float(scalar_keys["check_timeout_seconds"])  # type: ignore[arg-type]

    provider_data = data.get("provider")
    if provider_data is not None:
        if not isinstance(provider_data, dict):
            msg = "[provider] must be a TOML table"
            raise InvalidInputError(msg)
        result.provider = _apply_provider(result.provider, provider_data, source=source)

    result.source = source
    return result


def _apply_provider(
    settings: ProviderSettings, data: dict[str, object], *, source: str
) -> ProviderSettings:
    known = {
        "name",
        "endpoint",
        "model",
        "api_key_env",
        "timeout_seconds",
        "max_retries",
        "temperature",
        "max_context_chars",
        "enabled",
    }
    unknown = set(data) - known
    if unknown:
        msg = f"unknown [provider] key(s) in {source}: {sorted(unknown)}"
        raise InvalidInputError(msg)
    if "api_key" in data or "token" in data or "secret" in data:
        msg = (
            f"refusing to read a credential from {source}: provider keys must be supplied "
            "via environment variables named by 'api_key_env'"
        )
        raise InvalidInputError(msg)
    updated = settings
    for key, value in data.items():
        if key in {"timeout_seconds", "temperature", "max_context_chars", "max_retries"}:
            setattr(updated, key, float(value) if key == "timeout_seconds" else int(value))  # type: ignore[arg-type]
        elif key == "enabled":
            updated.enabled = bool(value)
        else:
            setattr(updated, key, str(value))
    return updated


def _apply_env(config: AppConfig, env: dict[str, str]) -> AppConfig:
    def present(name: str) -> str | None:
        value = env.get(f"{CONFIG_ENV_PREFIX}{name}")
        return value if value not in (None, "") else None

    if (value := present("DB")) is not None:
        config.database_path = Path(value)
    if (value := present("LOG_LEVEL")) is not None:
        config.log_level = _validate_log_level(value)
    if present("NO_COLOR") is not None:
        config.color = False
    if present("JSON") is not None:
        config.json_output = True
    if (value := present("PREFER_DOCKER")) is not None:
        if value.lower() in {"0", "false", "no", "off"}:
            config.prefer_docker = False
        elif value.lower() in {"1", "true", "yes", "on"}:
            config.prefer_docker = True
        else:
            msg = f"OPENMEDIC_PREFER_DOCKER must be a boolean, got {value!r}"
            raise UsageError(msg)

    provider = config.provider
    if (value := present("PROVIDER_TYPE")) is not None:
        provider.name = value
        provider.enabled = value.lower() not in {"none", "disabled", ""}
    if (value := present("PROVIDER_ENDPOINT")) is not None:
        provider.endpoint = value
    if (value := present("PROVIDER_MODEL")) is not None:
        provider.model = value
    if (value := present("PROVIDER_API_KEY_ENV")) is not None:
        provider.api_key_env = value
    if (value := present("PROVIDER_TIMEOUT")) is not None:
        provider.timeout_seconds = float(value)
    config.provider = provider
    return config
