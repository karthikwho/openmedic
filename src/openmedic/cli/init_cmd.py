"""``openmedic init`` — non-destructive project initialisation.

The roadmap is explicit that ``init`` validates configuration and discovers available
checks; it is **not** a project scaffolder. It never writes source files, never modifies
a user's repository, and only ever writes an OpenMedic-owned config file when the caller
passes ``--write``. By default it is a pure read-only health check.
"""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..domain.errors import UsageError
from .config import AppConfig

CONFIG_TEMPLATE = """\
# OpenMedic project configuration.
# Credentials are never stored here — see .env.example.
[openmedic]
database_path = "data/openmedic.db"
log_level = "WARNING"
prefer_docker = true
dry_run_by_default = true
max_files_changed = 5
require_review_above = "medium"
check_timeout_seconds = 300.0

# Optional model provider. Absent means deterministic-only operation.
# [provider]
# name = "openai-compatible"        # or "none"
# endpoint = "https://api.example.com/v1"
# model = "gpt-4o-mini"
# api_key_env = "OPENMEDIC_PROVIDER_API_KEY"   # name of the env var holding the key
# timeout_seconds = 30.0
# enabled = true
"""


@dataclass(slots=True)
class RuntimeReport:
    """Availability of one external runtime."""

    name: str
    available: bool
    detail: str = ""


@dataclass(slots=True)
class InitReport:
    """Everything ``init`` discovered."""

    config_source: str
    database_path: str
    database_writable: bool
    runtimes: list[RuntimeReport] = field(default_factory=list)
    checks_discovered: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    wrote_config: bool = False
    created_database: bool = False

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable copy of the report."""
        return {
            "config_source": self.config_source,
            "database_path": self.database_path,
            "database_writable": self.database_writable,
            "runtimes": [
                {"name": r.name, "available": r.available, "detail": r.detail}
                for r in self.runtimes
            ],
            "checks_discovered": list(self.checks_discovered),
            "warnings": list(self.warnings),
            "wrote_config": self.wrote_config,
            "created_database": self.created_database,
        }


def _probe_runtimes() -> list[RuntimeReport]:
    """Report which external tools are actually present on this machine."""
    probes: list[RuntimeReport] = []
    for name in ("git", "docker", "ruff", "pytest"):
        path = shutil.which(name)
        if path:
            probes.append(RuntimeReport(name=name, available=True, detail=path))
        else:
            probes.append(
                RuntimeReport(
                    name=name,
                    available=False,
                    detail="not found on PATH — features that need it will report it clearly",
                )
            )
    probes.append(
        RuntimeReport(
            name="python",
            available=True,
            detail=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
    )
    return probes


def _discover_checks(project_root: Path) -> list[str]:
    """Read-only discovery of runnable project checks.

    Inspects ``pyproject.toml``/``pytest.ini``/``ruff.toml`` only. Nothing is executed.
    """
    found: list[str] = []
    pyproject = project_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            import tomllib

            with pyproject.open("rb") as handle:
                data = tomllib.load(handle)
            tool = data.get("tool", {})
            if "pytest" in tool:
                found.append("pytest")
            ruff = tool.get("ruff", {})
            lint = ruff.get("lint", {})
            if lint.get("select"):
                found.append("ruff-lint")
            if ruff.get("format"):
                found.append("ruff-format")
        except (tomllib.TOMLDecodeError, OSError):
            found.append("(pyproject.toml present but unreadable)")
    if (project_root / "pytest.ini").is_file():
        found.append("pytest")
    if (project_root / "requirements.txt").is_file():
        found.append("pip-check")
    return sorted(set(found))


def run_init(
    config: AppConfig,
    *,
    project_root: Path | None = None,
    write_config: bool = False,
    create_database: bool = True,
) -> InitReport:
    """Perform the non-destructive initialisation and report what was found.

    Only OpenMedic-owned artifacts are ever created: the config file (only with
    ``write_config``) and the local incident database, which lives in a gitignored
    ``data/`` directory.
    """
    root = project_root or Path.cwd()
    report = InitReport(
        config_source=config.source,
        database_path=str(config.database_path),
        database_writable=False,
    )

    # Locate the config file that was actually used, if any. `source` holds either the
    # path that was read or one of the sentinels "defaults"/"environment".
    config_file: Path | None = None
    if config.source not in {"defaults", "environment"}:
        config_file = Path(config.source)
        if not config_file.is_absolute():
            config_file = root / config_file

    if write_config:
        target = config_file or (root / ".openmedic.toml")
        if target.exists():
            msg = f"refusing to overwrite existing config file {target}"
            raise UsageError(msg)
        target.write_text(CONFIG_TEMPLATE, encoding="utf-8")
        report.wrote_config = True
        report.warnings.append(f"wrote configuration template to {target}")
    elif config_file is None:
        report.warnings.append("no project config file found; running on defaults and environment")

    db_path = config.database_path
    if not db_path.is_absolute():
        db_path = root / db_path

    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        probe = db_path.parent / ".openmedic-write-probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink()
        report.database_writable = True
    except OSError as exc:
        report.warnings.append(f"database directory is not writable: {exc}")

    if create_database and report.database_writable:
        try:
            from ..persistence import init_db  # imported lazily: init stays cheap

            connection = init_db(db_path)
            connection.close()
            report.created_database = True
        except Exception as exc:
            report.warnings.append(f"could not initialise the incident database: {exc}")

    report.runtimes = _probe_runtimes()
    report.checks_discovered = _discover_checks(root)

    if not any(r.available and r.name == "docker" for r in report.runtimes):
        report.warnings.append(
            "Docker is unavailable: validation will use constrained local subprocess "
            "isolation, which is NOT a hardened sandbox"
        )
    if not any(r.available and r.name == "pytest" for r in report.runtimes):
        report.warnings.append(
            "pytest is unavailable: validation checks requiring it will be skipped"
        )
    if not any(r.available and r.name == "git" for r in report.runtimes):
        report.warnings.append("git is unavailable: disposable-worktree isolation cannot be used")

    return report


def render_init_report(report: InitReport) -> str:
    """Render :class:`InitReport` as human-readable text."""
    lines = [
        "OpenMedic initialisation check",
        "==============================",
        f"config source : {report.config_source}",
        f"database path : {report.database_path}"
        + ("" if report.database_writable else "  (NOT writable)"),
        f"database init : {'created' if report.created_database else 'not created'}",
        "",
        "Runtimes:",
    ]
    lines.extend(
        f"  {r.name:<8} {'ok' if r.available else 'missing'}  {r.detail}" for r in report.runtimes
    )
    lines.append("")
    lines.append(
        "Checks discovered: "
        + (", ".join(report.checks_discovered) if report.checks_discovered else "none")
    )
    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {w}" for w in report.warnings)
    return "\n".join(lines)
