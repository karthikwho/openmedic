"""The ``openmedic`` command-line interface.

Design rules enforced here:

* Command handlers stay **thin**. All orchestration lives in
  :mod:`openmedic.application.services`.
* Layer imports happen **inside** handlers, not at module import time. That keeps
  ``openmedic --help`` fast and guarantees a CLI-only install never pulls in the optional
  API dependencies.
* Every command supports ``--json`` for automation. In JSON mode stdout carries only the
  payload; human diagnostics go to stderr.
* Repair defaults to dry-run. Applying changes requires an explicit flag *and* a policy
  path.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from ..domain.errors import OpenMedicError
from . import exit_codes
from .exit_codes import exit_code_help
from .init_cmd import render_init_report, run_init
from .output import Output, configure_logging

app = typer.Typer(
    name="openmedic",
    help=(
        "Local-first CI/CD failure diagnosis and safe recovery.\n\n"
        "Diagnosis is deterministic and works offline. Model providers are optional "
        "enrichment and are never required.\n\n"
        "Exit codes:\n"
        f"{exit_code_help()}"
    ),
    add_completion=False,
    no_args_is_help=False,
    # The callback must run even when a command follows, so that `--version` and the
    # shared options are handled there. Typer would otherwise fail with
    # "Missing command." before ever invoking it.
    invoke_without_command=True,
    rich_markup_mode="rich",
)

incidents_app = typer.Typer(
    name="incidents", help="Inspect the local incident history.", add_completion=False
)
providers_app = typer.Typer(
    name="providers", help="Inspect configured model providers.", add_completion=False
)
github_app = typer.Typer(
    name="github", help="GitHub Actions integration (read-only by default).", add_completion=False
)

app.add_typer(incidents_app, name="incidents")
app.add_typer(providers_app, name="providers")
app.add_typer(github_app, name="github")

State = dict[str, Any]


@app.callback()
def main(
    ctx: typer.Context,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit machine-readable JSON on stdout.")
    ] = False,
    db: Annotated[
        Path | None, typer.Option("--db", help="Path to the local incident database.")
    ] = None,
    log_level: Annotated[
        str | None, typer.Option("--log-level", help="DEBUG, INFO, WARNING, ERROR, CRITICAL.")
    ] = None,
    no_color: Annotated[
        bool, typer.Option("--no-color", help="Disable ANSI colour in human output.")
    ] = False,
    show_version: Annotated[
        bool,
        typer.Option("--version", help="Show the version and exit.", is_eager=True),
    ] = False,
) -> None:
    """Global options shared by every command."""
    if show_version:
        from .. import __version__

        typer.echo(__version__)
        raise typer.Exit
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit
    from .config import load_config

    config = load_config().with_overrides(
        database_path=db, log_level=log_level, json_output=json_output, color=not no_color
    )
    configure_logging(config.log_level)
    ctx.obj = {"config": config, "output": Output(json_mode=config.json_output, color=config.color)}


def _output(ctx: typer.Context) -> Output:
    return ctx.obj["output"]


def _config(ctx: typer.Context) -> Any:
    return ctx.obj["config"]


def _services(ctx: typer.Context) -> Any:
    """Build application services and close them when the command's context unwinds.

    Without this the SQLite connection stays open until the interpreter exits, which
    leaks file descriptors in long-lived embedders and trips ResourceWarning in tests.
    """
    from ..application.services import Services

    services = Services.from_config(_config(ctx))
    ctx.call_on_close(services.close)
    return services


@app.command()
def init(
    ctx: typer.Context,
    write_config: Annotated[
        bool, typer.Option("--write", help="Write a commented .openmedic.toml template.")
    ] = False,
) -> None:
    """Validate configuration and report available runtimes (never destructive)."""
    config = _config(ctx)
    report = run_init(config, write_config=write_config)
    if config.json_output:
        _output(ctx).emit("initialisation check", report.to_dict())
    else:
        _output(ctx).emit(render_init_report(report))


@app.command()
def diagnose(
    ctx: typer.Context,
    log_file: Annotated[Path, typer.Argument(help="Path to a CI log, or '-' for stdin.")],
    repository: Annotated[str | None, typer.Option("--repository", "-r")] = None,
    run_id: Annotated[str | None, typer.Option("--run-id")] = None,
    workflow: Annotated[str | None, typer.Option("--workflow", "-w")] = None,
    step: Annotated[str | None, typer.Option("--step", "-s")] = None,
) -> None:
    """Diagnose a local CI log file. Works offline with no provider configured."""
    text = _read_log(log_file)
    services = _services(ctx)
    diagnosis = services.diagnose_text(
        text,
        repository=repository,
        run_id=run_id,
        workflow_name=workflow,
        failed_step=step,
    )
    _output(ctx).emit(
        services.render_diagnosis(diagnosis, color=_config(ctx).color),
        services.diagnosis_payload(diagnosis),
    )


@app.command()
def ingest(
    ctx: typer.Context,
    event_file: Annotated[Path, typer.Argument(help="Path to a JSON FailureEvent.")],
) -> None:
    """Ingest a JSON FailureEvent and store it as an incident."""
    if not event_file.is_file():
        from ..domain.errors import InvalidInputError

        msg = f"event file not found: {event_file}"
        raise InvalidInputError(msg)
    services = _services(ctx)
    record = services.ingest_event_json(event_file.read_text(encoding="utf-8"))
    _output(ctx).emit(
        f"stored incident {record.incident_id} (state: {record.state.value})",
        {"incident_id": record.incident_id, "state": record.state.value},
    )


@incidents_app.command("list")
def incidents_list(
    ctx: typer.Context,
    state: Annotated[str | None, typer.Option("--state", help="Filter by lifecycle state.")] = None,
    limit: Annotated[int, typer.Option("--limit", min=1)] = 20,
) -> None:
    """List stored incidents, newest first."""
    services = _services(ctx)
    records = services.list_incidents(state=state, limit=limit)
    _output(ctx).emit(
        services.render_incident_table(records), {"incidents": services.incident_payloads(records)}
    )


@incidents_app.command("show")
def incidents_show(
    ctx: typer.Context,
    incident_id: Annotated[str, typer.Argument()],
) -> None:
    """Show one incident with evidence, attempts, and validation."""
    services = _services(ctx)
    record = services.get_incident(incident_id)
    _output(ctx).emit(
        services.render_incident(record, color=_config(ctx).color),
        services.incident_payloads([record])[0],
    )


@providers_app.command("list")
def providers_list(ctx: typer.Context) -> None:
    """List configured providers and whether each is usable."""
    services = _services(ctx)
    _output(ctx).emit(services.render_providers(), services.provider_payload())


@providers_app.command("test")
def providers_test(
    ctx: typer.Context,
    provider: Annotated[str, typer.Argument(help="Provider name.")],
) -> None:
    """Check that a provider is configured and reachable (never required)."""
    services = _services(ctx)
    outcome = services.test_provider(provider)
    _output(ctx).emit(outcome.message, outcome.payload)


@app.command()
def repair(
    ctx: typer.Context,
    incident_id: Annotated[str, typer.Argument()],
    dry_run: Annotated[
        bool, typer.Option("--dry-run/--apply", help="Dry-run (propose only) is the default.")
    ] = True,
) -> None:
    """Propose (or, with --apply, stage) a bounded remediation for an incident."""
    services = _services(ctx)
    outcome = services.repair(incident_id, apply=not dry_run)
    _output(ctx).emit(outcome.message, outcome.payload)
    if outcome.exit_code:
        # Emitted first so a JSON caller still gets the reason, then the documented
        # non-zero status: an unresolved repair must never read as success.
        raise typer.Exit(outcome.exit_code)


@app.command()
def validate(
    ctx: typer.Context,
    incident_id: Annotated[str, typer.Argument()],
) -> None:
    """Validate the current candidate patch for an incident in an isolated workspace."""
    services = _services(ctx)
    outcome = services.validate(incident_id)
    _output(ctx).emit(outcome.message, outcome.payload)


@github_app.command("run")
def github_run(
    ctx: typer.Context,
    repository: Annotated[str, typer.Argument(help="owner/repo.")],
    run_id: Annotated[str, typer.Argument(help="Workflow run id.")],
) -> None:
    """Ingest a GitHub Actions run (read-only) and diagnose it."""
    services = _services(ctx)
    record = services.ingest_github_run(repository, run_id)
    _output(ctx).emit(
        services.render_incident(record, color=_config(ctx).color),
        services.incident_payloads([record])[0],
    )


@app.command()
def benchmark(
    ctx: typer.Context,
    cases_dir: Annotated[
        Path | None, typer.Argument(help="Directory of labelled benchmark cases.")
    ] = None,
) -> None:
    """Run the deterministic diagnosis benchmark over committed labelled cases.

    The corpus and its targets ship inside the package, so this works from a source
    checkout and from an installed wheel alike. Every committed target in
    ``expected.json`` is enforced: missing one exits 4, so a regression fails CI instead
    of being reported as a number nobody acts on.
    """
    services = _services(ctx)
    run = services.benchmark(cases_dir)
    _output(ctx).emit(run.to_text(), run.to_dict())
    if not run.passed:
        missed = ", ".join(check.name for check in run.verdict.failures)
        _output(ctx).error(f"benchmark targets not met: {missed}")
        raise typer.Exit(exit_codes.VALIDATION_FAILED)


def _read_log(path: Path) -> str:
    """Read a log from a file or stdin ('-')."""
    from ..domain.errors import InvalidInputError

    if str(path) == "-":
        data = sys.stdin.read()
        if not data.strip():
            msg = "no input received on stdin"
            raise InvalidInputError(msg)
        return data
    if not path.is_file():
        msg = f"log file not found: {path}"
        raise InvalidInputError(msg)
    return path.read_text(encoding="utf-8", errors="replace")


def run() -> None:
    """Console entry point: map domain errors to documented exit codes."""
    try:
        app()
    except OpenMedicError as exc:
        typer.echo(f"error: {exc.message}", err=True)
        if exc.detail:
            typer.echo(f"detail: {exc.detail}", err=True)
        raise SystemExit(exc.exit_code) from exc
    except KeyboardInterrupt:  # pragma: no cover - interactive
        typer.echo("interrupted", err=True)
        raise SystemExit(130) from None


if __name__ == "__main__":  # pragma: no cover
    run()


__all__ = ["app", "exit_codes", "run"]
