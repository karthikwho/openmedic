"""CLI configuration resolution: file < environment < flags, and no secrets in files."""

from __future__ import annotations

from pathlib import Path

import pytest

from openmedic.cli.config import AppConfig, load_config
from openmedic.domain.errors import InvalidInputError, UsageError


def test_defaults_load_without_any_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("OPENMEDIC_DB", raising=False)
    config = load_config()
    assert config.source == "defaults"
    assert config.dry_run_by_default is True
    assert config.provider.enabled is False


def test_project_config_file_is_read(tmp_path: Path) -> None:
    (tmp_path / ".openmedic.toml").write_text(
        '[openmedic]\ndatabase_path = "custom/incidents.db"\nlog_level = "DEBUG"\n',
        encoding="utf-8",
    )
    config = load_config(path=tmp_path / ".openmedic.toml")
    assert config.database_path.name == "incidents.db"
    assert config.log_level == "DEBUG"


def test_environment_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".openmedic.toml").write_text(
        '[openmedic]\ndatabase_path = "from-file.db"\n', encoding="utf-8"
    )
    env = {"OPENMEDIC_DB": "from-env.db"}
    config = load_config(path=tmp_path / ".openmedic.toml", env=env)
    assert config.database_path.name == "from-env.db"


def test_flags_override_everything(tmp_path: Path) -> None:
    (tmp_path / ".openmedic.toml").write_text(
        '[openmedic]\ndatabase_path = "from-file.db"\n', encoding="utf-8"
    )
    env = {"OPENMEDIC_DB": "from-env.db"}
    config = load_config(path=tmp_path / ".openmedic.toml", env=env).with_overrides(
        database_path=Path("from-flag.db")
    )
    assert config.database_path.name == "from-flag.db"


def test_unknown_config_key_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / ".openmedic.toml"
    path.write_text("[openmedic]\ndatabase_path = 'x.db'\ntypo_key = 1\n", encoding="utf-8")
    with pytest.raises(InvalidInputError, match="typo_key"):
        load_config(path=path)


def test_invalid_toml_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / ".openmedic.toml"
    path.write_text("this is not = = toml\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        load_config(path=path)


def test_provider_config_does_not_accept_a_credential(tmp_path: Path) -> None:
    path = tmp_path / ".openmedic.toml"
    path.write_text(
        '[openmedic.provider]\nname = "openai-compatible"\napi_key = "sk-should-not-be-here"\n',
        encoding="utf-8",
    )
    with pytest.raises(InvalidInputError, match="api_key"):
        load_config(path=path)


def test_provider_api_key_env_only_names_a_variable(tmp_path: Path) -> None:
    path = tmp_path / ".openmedic.toml"
    path.write_text(
        '[openmedic.provider]\nname = "openai-compatible"\napi_key_env = "MY_KEY_VAR"\n'
        'endpoint = "https://example.invalid/v1"\nmodel = "m"\nenabled = true\n',
        encoding="utf-8",
    )
    config = load_config(path=path)
    assert config.provider.api_key_env == "MY_KEY_VAR"
    assert config.provider.enabled is True


def test_invalid_log_level_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / ".openmedic.toml"
    path.write_text("[openmedic]\nlog_level = 'CHATTY'\n", encoding="utf-8")
    with pytest.raises(InvalidInputError):
        load_config(path=path)


def test_invalid_boolean_env_is_rejected() -> None:
    with pytest.raises(UsageError):
        load_config(env={"OPENMEDIC_PREFER_DOCKER": "maybe"})


def test_provider_absent_is_normal_not_an_error() -> None:
    config = load_config(env={})
    assert config.provider.enabled is False
    assert config.provider.name == "none"


def test_unknown_provider_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / ".openmedic.toml"
    path.write_text("[openmedic.provider]\nunknowwn = 1\n", encoding="utf-8")
    with pytest.raises(InvalidInputError, match="unknowwn"):
        load_config(path=path)


def test_with_overrides_ignores_none() -> None:
    base = AppConfig()
    assert base.with_overrides(database_path=None) is base
