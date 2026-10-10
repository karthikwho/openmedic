"""Use-case orchestration shared by the CLI and the optional API.

Both transports are deliberately thin. Everything that decides *what happens* lives here,
so a bug cannot exist in one interface but not the other.

Layer direction is strictly downward: services → domain/forensics → layers. No layer
imports this module, which is what keeps the CLI and API interchangeable.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..domain.contracts import utc_now
from ..domain.enums import LifecycleState
from ..domain.errors import (
    IntegrationUnavailableError,
    InvalidInputError,
    OpenMedicError,
    UnresolvedRepairError,
    ValidationFailedError,
)
from ..domain.lifecycle import apply_transition, can_transition
from ..domain.redaction import redact


@dataclass(slots=True)
class Outcome:
    """Result of a command that may have partially failed.

    ``exit_code`` is the process status a transport should report. Zero means the command
    did what was asked of it. A non-zero value means the *requested work was not
    completed* — the numbers and their meanings live in ``openmedic.cli.exit_codes``, and
    this layer only states which one applies, so a caller that checks the exit code is
    never told an unresolved repair succeeded. The payload is still returned alongside a
    non-zero code so an automated caller can report why.
    """

    message: str
    payload: dict[str, object]
    exit_code: int = 0


class Services:
    """Application service graph.

    Constructed once per process (and per request in the API) with an explicit
    :class:`~openmedic.cli.config.AppConfig`. All side effects are bounded to the
    configured database path and to disposable temporary workspaces.
    """

    def __init__(
        self,
        config: Any,
        *,
        repository: Any = None,
        engine: Any = None,
        providers: Any = None,
        reporter: Any = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.config = config
        self._repository = repository
        self._engine = engine
        self._providers = providers
        self._reporter = reporter
        self._clock = clock

    # -- construction -------------------------------------------------------------

    @classmethod
    def from_config(cls, config: Any) -> Services:
        """Build services from a parsed configuration object."""
        return cls(config)

    @classmethod
    def default(cls) -> Services:  # pragma: no cover - used by the API
        """Build services from the configuration loaded off disk."""
        from ..cli.config import load_config

        return cls.from_config(load_config())

    # -- lazily built collaborators ----------------------------------------------

    @property
    def repository(self) -> Any:
        """The incident repository, opened on first use."""
        if self._repository is None:
            from ..persistence import IncidentRepository

            db_path = Path(self.config.database_path)
            if not db_path.is_absolute():
                db_path = Path.cwd() / db_path
            db_path.parent.mkdir(parents=True, exist_ok=True)
            self._repository = IncidentRepository(db_path)
        return self._repository

    @property
    def engine(self) -> Any:
        """Return the diagnosis engine, constructed on first use."""
        if self._engine is None:
            from ..diagnosis import DiagnosisEngine

            self._engine = DiagnosisEngine()
        return self._engine

    @property
    def providers(self) -> Any:
        """Return the provider registry, resolved from the environment on first use."""
        if self._providers is None:
            from ..providers import ProviderRegistry

            settings = self.config.provider
            # from_environment is an instance method that merges into a seeded registry,
            # so start from an empty one rather than calling it on the class.
            registry = ProviderRegistry().from_environment(dict(os.environ))
            if not registry.available() and settings.name not in {"", "none"}:
                from ..providers import ProviderConfig

                registry.register(
                    ProviderConfig(
                        name=settings.name,
                        endpoint=settings.endpoint,
                        model=settings.model,
                        api_key_env=settings.api_key_env,
                        timeout_seconds=settings.timeout_seconds,
                        max_retries=settings.max_retries,
                        temperature=settings.temperature,
                        max_context_chars=settings.max_context_chars,
                        enabled=settings.enabled,
                    )
                )
            self._providers = registry
        return self._providers

    @property
    def reporter(self) -> Any:
        """Return the terminal reporter, built from the configured colour preference."""
        if self._reporter is None:
            from ..reporting import TerminalReporter

            self._reporter = TerminalReporter(color=bool(self.config.color))
        return self._reporter

    def close(self) -> None:
        """Close the incident repository if it was opened; calling this twice is harmless."""
        if self._repository is not None:
            self._repository.close()
            self._repository = None

    def __enter__(self) -> Services:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- diagnosis ----------------------------------------------------------------

    def diagnose_text(
        self,
        text: str,
        *,
        repository: str | None = None,
        run_id: str | None = None,
        workflow_name: str | None = None,
        failed_step: str | None = None,
    ) -> Any:
        """Ingest a raw log and diagnose it. Offline; no provider is required."""
        from ..ingestion import ingest_log_text

        event = ingest_log_text(
            text,
            repository=repository,
            run_id=run_id,
            workflow_name=workflow_name,
            failed_step=failed_step,
        )
        return self.diagnose_event(event)

    def diagnose_event(self, event: Any) -> Any:
        """Run deterministic diagnosis, with optional provider enrichment."""
        diagnosis = self.engine.diagnose(event)
        return self._enrich(event, diagnosis)

    def _enrich(self, event: Any, diagnosis: Any) -> Any:
        """Let a configured provider annotate the diagnosis.

        Enrichment is strictly advisory. A provider can never change risk policy, can
        never override the deterministic result's failure type, and cannot fabricate
        quotes. Any provider failure is swallowed and recorded as a limitation so the
        deterministic path always survives.
        """
        provider = self._select_provider()
        if provider is None:
            return diagnosis
        try:
            from ..providers import ProviderContext

            context = ProviderContext(
                event=event,
                deterministic_diagnosis=diagnosis,
                request_id=f"{event.resolved_incident_id}:{diagnosis.rule_id}",
                allowed_quote_lines=frozenset(event.logs.splitlines()),
            )
            result = provider.diagnose(event, context=context)
        except OpenMedicError as exc:
            limitations = [*diagnosis.limitations, f"provider enrichment skipped: {exc.message}"]
            return diagnosis.model_copy(update={"limitations": limitations})

        return diagnosis.model_copy(
            update={
                "probable_cause": f"{diagnosis.probable_cause} — {result.probable_cause}"
                if result.probable_cause
                else diagnosis.probable_cause,
                "limitations": [
                    *diagnosis.limitations,
                    *result.limitations,
                    "model output is advisory only and cannot change risk or validation",
                ],
                "provider_used": True,
            }
        )

    def _select_provider(self) -> Any:
        try:
            available = self.providers.available()
        except Exception:
            return None
        if not available:
            return None
        return self.providers.get(available[0])

    # -- persistence --------------------------------------------------------------

    def ingest_event_json(self, text: str) -> Any:
        """Parse a FailureEvent from JSON text and store it as an incident."""
        from ..ingestion import ingest_event_json

        event = ingest_event_json(text)
        return self._store(event)

    def ingest_log(self, text: str, **metadata: Any) -> Any:
        """Normalise raw CI log text into a FailureEvent and store it as an incident."""
        from ..ingestion import ingest_log_text

        return self._store(ingest_log_text(text, **metadata))

    def ingest_github_run(self, repository: str, run_id: str) -> Any:
        """Read-only ingestion of a GitHub Actions run, then diagnosis."""
        from ..github import GitHubClient, ingest_run

        token = os.environ.get("OPENMEDIC_GITHUB_TOKEN")
        if not token:
            msg = (
                "set OPENMEDIC_GITHUB_TOKEN to ingest a GitHub Actions run; "
                "local log ingestion works without it"
            )
            raise IntegrationUnavailableError(msg)
        client = GitHubClient(token=token)
        event = ingest_run(client, repository, run_id)
        record = self._store(event)
        self.diagnose_stored(record.incident_id)
        return self.get_incident(record.incident_id)

    def _store(self, event: Any) -> Any:
        """Persist an incident for ``event``, transitioning to DIAGNOSING.

        Re-ingesting an event that has already produced an incident returns the stored
        incident exactly as it stands. Ingestion is an *arrival* event, not a reset: the
        same event reaching the tool a second time must never discard a diagnosis, a
        remediation attempt, a validation, or the state history, all of which the rest of
        the product treats as append-only. A genuinely new failure carries a different
        idempotency key and therefore opens a new incident as usual.
        """
        candidate = _new_record(event, self._clock())
        existing = self.repository.find_by_idempotency_key(candidate.idempotency_key)
        if existing is not None:
            if existing.state is not LifecycleState.RECEIVED:
                # Already arrived and progressed (or arrived and was recorded): leave it.
                return existing
            # Interrupted between insert and the first transition: finish that one step
            # rather than starting over, so a retry cannot leave a stuck RECEIVED row.
            apply_transition(
                existing, LifecycleState.DIAGNOSING, reason="ingested", at=self._clock()
            )
            return self.repository.upsert_incident(existing)

        record = self.repository.upsert_incident(candidate)
        apply_transition(
            record,
            LifecycleState.DIAGNOSING,
            reason="ingested",
            at=self._clock(),
        )
        return self.repository.upsert_incident(record)

    def list_incidents(self, *, state: str | None = None, limit: int = 20) -> list[Any]:
        """List stored incidents newest first, optionally filtered by lifecycle state."""
        parsed = _parse_state(state)
        return self.repository.list_incidents(state=parsed, limit=limit)

    def get_incident(self, incident_id: str) -> Any:
        """Return one incident, raising InvalidInputError when the id is unknown."""
        record = self.repository.get_incident(incident_id)
        if record is None:
            msg = f"no incident found with id {incident_id!r}"
            raise InvalidInputError(msg)
        return record

    def diagnose_stored(self, incident_id: str) -> Any:
        """Diagnose a stored incident and record the diagnosis.

        ``record_diagnosis`` already walks the incident to ``diagnosed``, so the only
        transition left is the one a review-requiring diagnosis needs. Requesting the
        state the record is already in would be an illegal self-transition, and a
        terminal incident is not reopened by a re-run.
        """
        record = self.get_incident(incident_id)
        diagnosis = self.diagnose_event(record.event)
        record = self.repository.record_diagnosis(record.incident_id, diagnosis, at=self._clock())
        next_state = (
            LifecycleState.REQUIRES_HUMAN_REVIEW
            if diagnosis.requires_human_review
            else LifecycleState.DIAGNOSED
        )
        if can_transition(record.state, next_state):
            apply_transition(record, next_state, reason=diagnosis.probable_cause, at=self._clock())
            record = self.repository.upsert_incident(record)
        return record

    # -- remediation and validation ----------------------------------------------

    def repair(self, incident_id: str, *, apply: bool = False) -> Outcome:
        """Propose (and optionally stage) a bounded remediation.

        ``apply=False`` is a dry run: it never writes to the user's tree. ``apply=True``
        writes only into a disposable worktree.
        """
        from ..remediation import propose_remediation

        record = self.get_incident(incident_id)
        diagnosis = record.latest_diagnosis
        if diagnosis is None:
            record = self.diagnose_stored(incident_id)
            diagnosis = record.latest_diagnosis
        if diagnosis is None:  # pragma: no cover - engine always returns something
            msg = "diagnosis produced no result"
            raise UnresolvedRepairError(msg)

        outcome = propose_remediation(record.event, diagnosis, repo_root=Path.cwd())
        if outcome.attempt is None:
            refusal = outcome.rejected_reason or "no safe remediation available"
            if can_transition(record.state, LifecycleState.REQUIRES_HUMAN_REVIEW):
                apply_transition(
                    record,
                    LifecycleState.REQUIRES_HUMAN_REVIEW,
                    reason=refusal,
                    at=self._clock(),
                )
                self.repository.upsert_incident(record)
            msg = refusal
            payload = {
                "incident_id": incident_id,
                "proposal": None,
                "reason": msg,
            }
            # `docs/TRD.md` section 5 requires a non-zero exit for an unresolved repair.
            # The more specific code wins: when the diagnosis flagged the incident for
            # review, the honest answer is that a person has to look at it, not that the
            # tool merely failed to find a fix.
            exit_code = (
                7 if diagnosis.requires_human_review else 6  # human review / unresolved
            )
            return Outcome(f"no remediation proposed for {incident_id}: {msg}", payload, exit_code)

        attempt = outcome.attempt
        # Recording the attempt is what lands the incident at `remediation_pending`: a
        # candidate patch now exists, and nothing has been applied yet. Walking it to
        # `remediating` is reserved for the moment checks actually run.
        record = self.repository.record_attempt(record.incident_id, attempt, at=self._clock())

        if not apply:
            return Outcome(_render_proposal(attempt), _proposal_payload(attempt))

        # Staging is the only path that touches a workspace, and it is disposable.
        return self._stage(record, attempt)

    def _stage(self, record: Any, attempt: Any) -> Outcome:
        from ..remediation import apply_patch_proposal
        from ..validation import (
            DEFAULT_POLICY,
            ValidationRunner,
            disposable_worktree,
        )

        source = Path.cwd()
        with tempfile.TemporaryDirectory(prefix="openmedic-worktree-") as tmp:
            # The destination must not exist yet: `disposable_worktree` refuses to
            # overwrite, which is what stops a caller validating in a real working tree.
            worktree = disposable_worktree(source, Path(tmp) / "worktree")
            apply_patch_proposal(_proposal_for(attempt, worktree=worktree), worktree=worktree)
            runner = ValidationRunner(DEFAULT_POLICY)
            result = runner.validate(attempt, worktree=worktree, candidate_hash=attempt.patch_hash)

        record = self.repository.record_validation(record.incident_id, result, at=self._clock())
        next_state = LifecycleState.RECOVERED if result.passed else LifecycleState.FAILED
        try:
            apply_transition(record, next_state, reason=result.summary, at=self._clock())
        except OpenMedicError:
            # The transition table or recovery guard rejected this: record why.
            apply_transition(
                record,
                LifecycleState.REQUIRES_HUMAN_REVIEW,
                reason=f"validation could not be recorded as recovery: {result.summary}",
                at=self._clock(),
            )
        self.repository.upsert_incident(record)
        if not result.passed:
            raise ValidationFailedError(result.summary or "required validation checks did not pass")
        return Outcome(_render_validation(result), _validation_payload(result))

    def validate(self, incident_id: str) -> Outcome:
        """Validate the current candidate patch for an incident."""
        from ..validation import DEFAULT_POLICY, ValidationRunner, disposable_worktree

        record = self.get_incident(incident_id)
        attempt = record.attempts[-1] if record.attempts else None
        if attempt is None:
            msg = f"incident {incident_id} has no remediation attempt to validate"
            raise UnresolvedRepairError(msg)
        if attempt.patch_hash is None:
            msg = "the current attempt has no patch hash, so it cannot be bound to a validation"
            raise UnresolvedRepairError(msg)

        from ..remediation import apply_patch_proposal

        with tempfile.TemporaryDirectory(prefix="openmedic-worktree-") as tmp:
            worktree = disposable_worktree(Path.cwd(), Path(tmp) / "worktree")
            apply_patch_proposal(_proposal_for(attempt, worktree=worktree), worktree=worktree)
            result = ValidationRunner(DEFAULT_POLICY).validate(
                attempt, worktree=worktree, candidate_hash=attempt.patch_hash
            )

        record = self.repository.record_validation(record.incident_id, result, at=self._clock())
        if result.passed:
            target = LifecycleState.RECOVERED
        elif any(c.status.value == "skipped" for c in result.checks_executed):
            target = LifecycleState.REQUIRES_HUMAN_REVIEW
        else:
            target = LifecycleState.FAILED
        try:
            apply_transition(record, target, reason=result.summary, at=self._clock())
        except OpenMedicError:
            apply_transition(
                record,
                LifecycleState.REQUIRES_HUMAN_REVIEW,
                reason=f"validation could not be recorded as recovery: {result.summary}",
                at=self._clock(),
            )
        self.repository.upsert_incident(record)

        if not result.passed:
            raise ValidationFailedError(result.summary or "required validation checks did not pass")
        return Outcome(_render_validation(result), _validation_payload(result))

    # -- providers ----------------------------------------------------------------

    def provider_payload(self) -> dict[str, object]:
        """Describe configured and available providers without contacting the network."""
        registry = self.providers
        try:
            available = registry.available()
        except Exception:
            available = []
        try:
            described = registry.describe()
        except Exception:
            described = []
        return {"available": available, "configured": described}

    def render_providers(self) -> str:
        """Render the provider report for humans."""
        payload = self.provider_payload()
        available = payload["available"] or []
        configured = payload["configured"] or []
        lines = ["Configured providers:", "  (none)" if not configured else ""]
        for entry in configured if isinstance(configured, list) else []:
            name = entry.get("name", "?")
            enabled = entry.get("enabled")
            lines.append(f"  - {name} (enabled={enabled})")
        lines.append("")
        lines.append(
            "Available: " + (", ".join(available) if available else "none — deterministic only")
        )
        return "\n".join(lines)

    def test_provider(self, name: str) -> Outcome:
        """Report whether a named provider is configured; connectivity stays separate."""
        provider = self.providers.get(name)
        if provider is None:
            msg = f"provider {name!r} is not configured"
            raise IntegrationUnavailableError(msg)
        return Outcome(f"provider {name!r} is configured", {"provider": name, "configured": True})

    # -- reporting ----------------------------------------------------------------

    def render_diagnosis(self, diagnosis: Any, *, color: bool = True) -> str:
        """Render a diagnosis for humans, honouring the requested colour."""
        return _render_diagnosis_text(diagnosis, color=color)

    def diagnosis_payload(self, diagnosis: Any) -> dict[str, object]:
        """Return the JSON-serialisable payload for a diagnosis."""
        from ..reporting import diagnosis_dict

        return diagnosis_dict(diagnosis)

    def render_incident(self, record: Any, *, color: bool = True, json_mode: bool = False) -> str:
        """Render one incident as JSON, or as terminal output honouring colour."""
        if json_mode:
            from ..reporting import report_json

            return report_json(record)
        if color == bool(self.config.color):
            return self.reporter.render(record)
        from ..reporting import TerminalReporter

        return TerminalReporter(color=color).render(record)

    def render_incident_table(self, records: Iterable[Any]) -> str:
        """Render stored incidents as a fixed-width table for humans."""
        rows = list(records)
        if not rows:
            return "No incidents stored."
        header = f"{'INCIDENT':<20} {'STATE':<22} {'TYPE':<22} {'SEEN'}"
        lines = [header, "-" * len(header)]
        for record in rows:
            failure = (
                record.latest_diagnosis.failure_type.value
                if record.latest_diagnosis
                else record.event.failure_type.value
            )
            lines.append(
                f"{record.incident_id:<20} {record.state.value:<22} {failure:<22} "
                f"{record.updated_at.isoformat(timespec='seconds')}"
            )
        lines.append("")
        lines.append(f"{len(rows)} incident(s)")
        return "\n".join(lines)

    def incident_payloads(self, records: Iterable[Any]) -> list[dict[str, object]]:
        """Return the JSON payloads for a list of incidents."""
        from ..reporting import report_dict

        return [report_dict(record) for record in records]

    def markdown_report(self, record: Any) -> str:
        """Render one incident as an honest Markdown report."""
        from ..reporting import render_markdown

        return render_markdown(record)

    # -- intelligence -------------------------------------------------------------

    def benchmark(self, cases_dir: Path | None = None) -> Any:
        """Run the labelled diagnosis benchmark and check it against its targets.

        The corpus ships inside the package, so this works from a source checkout and
        from an installed wheel alike. The committed targets in ``expected.json`` are
        loaded and enforced: the returned run reports ``passed`` as False when any
        target is missed, and the CLI turns that into a non-zero exit status.
        """
        from ..intelligence import (
            BenchmarkRun,
            check_targets,
            load_cases,
            load_expected,
            load_targets,
            run_benchmark,
            validate_expected_matches_cases,
        )

        directory = cases_dir or _default_cases_dir()
        if not directory.is_dir():
            # The corpus is package data; a missing directory means a broken install
            # rather than an empty run, and an empty run would look like a perfect score.
            msg = (
                f"benchmark case directory not found: {directory}. Reinstall OpenMedic "
                "so the packaged corpus is present, or pass the directory of labelled "
                "cases as an argument."
            )
            raise InvalidInputError(msg)
        expectations = directory / "expected.json"
        targets = load_targets(expectations)
        cases = load_cases(directory)
        if not cases:
            msg = f"no benchmark cases found in {directory}"
            raise InvalidInputError(msg)
        validate_expected_matches_cases(load_expected(expectations), cases, source=expectations)
        report = run_benchmark(
            cases,
            diagnose=self.diagnose_event,
            build_event=_build_event,
        )
        return BenchmarkRun(
            cases_dir=directory,
            report=report,
            targets=targets,
            verdict=check_targets(report, targets),
        )

    def recurrences(self, *, min_count: int = 2) -> list[Any]:
        """Find failure fingerprints that recur across stored incidents."""
        from ..intelligence import find_recurrences

        return find_recurrences(self.repository.all_incidents(), min_count=min_count)

    def cascades(self) -> list[Any]:
        """Group incidents that look like one cascade of failures."""
        from ..intelligence import group_cascades

        return group_cascades(self.repository.all_incidents())


# ---------------------------------------------------------------------------
# Module-level helpers. Pure functions, so they are trivially testable.
# ---------------------------------------------------------------------------


def _parse_state(state: str | None) -> LifecycleState | None:
    if not state:
        return None
    try:
        return LifecycleState(state)
    except ValueError as exc:
        valid = ", ".join(s.value for s in LifecycleState)
        msg = f"unknown lifecycle state {state!r}; expected one of {valid}"
        raise InvalidInputError(msg) from exc


def _new_record(event: Any, at: datetime) -> Any:
    from ..domain import IncidentRecord

    return IncidentRecord(
        incident_id=event.resolved_incident_id,
        event=event,
        state=LifecycleState.RECEIVED,
        created_at=at,
        updated_at=at,
        idempotency_key=event.idempotency_key,
    )


def _build_event(text: str) -> Any:
    from ..ingestion import ingest_log_text

    return ingest_log_text(text)


def _default_cases_dir() -> Path:
    """Return the labelled corpus that ships inside the package.

    The cases are package data, not test data, so an installed wheel carries them and
    ``openmedic benchmark`` works outside a source checkout. The path is still returned
    when it is missing rather than swallowed, so the caller can report exactly what was
    absent instead of appearing to have run an empty benchmark.
    """
    from ..intelligence import default_cases_dir

    return default_cases_dir()


def _style(text: str, *, color: bool) -> str:
    """Wrap ``text`` in bold when colour is on, leaving plain output untouched."""
    if not color:
        return text
    return f"\033[1m{text}\033[0m"


def _render_diagnosis_text(diagnosis: Any, *, color: bool = False) -> str:
    """Render one diagnosis as text, styling labels only when ``color`` is set."""
    lines = [
        f"{_style('Failure type', color=color)} : {diagnosis.failure_type.value}",
        f"{_style('Probable cause', color=color)}: {diagnosis.probable_cause}",
        f"{_style('Confidence', color=color)}    : {diagnosis.confidence:.2f}",
        f"{_style('Recommended', color=color)}   : {diagnosis.recommended_action.value}",
        f"{_style('Risk level', color=color)}    : {diagnosis.risk_level.value}",
        f"{_style('Human review', color=color)}  : "
        + ("required" if diagnosis.requires_human_review else "not required"),
        f"{_style('Rule', color=color)}          : {diagnosis.rule_id} v{diagnosis.rule_version}",
        "",
        _style("Evidence:", color=color),
    ]
    if not diagnosis.evidence:
        lines.append("  (none)")
    for item in diagnosis.evidence:
        marker = " [inferred]" if item.inferred else ""
        lines.append(f"  - {item.source}: {item.quote}{marker}")
        lines.append(f"      {item.explanation}")
    lines.append("")
    lines.append(_style("Limitations:", color=color))
    lines.extend(f"  - {item}" for item in diagnosis.limitations)
    return "\n".join(lines)


def _render_proposal(attempt: Any) -> str:
    lines = [
        f"Proposed remediation ({attempt.attempt_id})",
        f"  rule      : {attempt.rule_id}",
        f"  summary   : {attempt.summary}",
        f"  rationale : {attempt.rationale}",
        f"  risk      : {attempt.risk_level.value}",
        f"  status    : {attempt.status.value}",
        f"  patch     : {attempt.patch_hash or '(none)'}",
        "",
        "Files changed:",
    ]
    lines.extend(
        f"  - {path}" for path in attempt.files_changed
    ) if attempt.files_changed else lines.append("  (none)")
    if attempt.patch_unified_diff:
        lines.extend(["", "Diff:", attempt.patch_unified_diff.rstrip()])
    return "\n".join(lines)


def _render_validation(result: Any) -> str:
    lines = [
        f"Validation outcome: {'PASSED' if result.passed else 'FAILED'}",
        f"  summary : {result.summary}",
        f"  patch   : {result.candidate_patch_hash or '(unbound)'}",
        f"  isolation: {result.execution.isolation_kind}",
    ]
    if result.execution.limitations:
        lines.append("  limitations:")
        lines.extend(f"    - {item}" for item in result.execution.limitations)
    lines.append("  checks:")
    for check in result.checks_executed:
        detail = f"exit={check.exit_code}" if check.exit_code is not None else ""
        lines.append(f"    - {check.name}: {check.status.value} {detail}".rstrip())
    return "\n".join(lines)


def _proposal_payload(attempt: Any) -> dict[str, object]:
    return {
        "incident_id": attempt.incident_id,
        "attempt_id": attempt.attempt_id,
        "rule_id": attempt.rule_id,
        "status": attempt.status.value,
        "risk_level": attempt.risk_level.value,
        "requires_human_review": attempt.requires_human_review,
        "patch_hash": attempt.patch_hash,
        "files_changed": list(attempt.files_changed),
        "unified_diff": redact(attempt.patch_unified_diff).text,
    }


def _validation_payload(result: Any) -> dict[str, object]:
    from ..reporting import validation_dict

    return validation_dict(result)


def _proposal_for(attempt: Any, *, worktree: Path) -> Any:
    """Rebuild a patch proposal from a persisted attempt.

    Reconstructed from the stored diff because the command may run in a different
    process from the one that produced it. The current content of each changed file
    comes from ``worktree``: a unified diff omits everything outside its context window,
    so the diff alone cannot recover a whole file. The rebuild must then reproduce the
    recorded ``patch_hash`` exactly — a patch whose text cannot be replayed is refused
    rather than approximated, so validation never runs against content nobody proposed.
    """
    from ..domain.errors import InvalidInputError
    from ..remediation import PatchProposal, parse_unified_diff

    contents = {path: _read_for_patch(worktree, path) for path in attempt.files_changed}
    files = parse_unified_diff(attempt.patch_unified_diff, contents=contents)
    proposal = PatchProposal(files=files, summary=attempt.summary, rationale=attempt.rationale)
    rebuilt = proposal.patch_hash()
    if rebuilt != attempt.patch_hash:
        msg = (
            f"cannot rebuild the patch for attempt {attempt.attempt_id}: the reconstructed "
            f"diff hashes to {rebuilt} but the recorded patch hash is {attempt.patch_hash}"
        )
        raise InvalidInputError(msg)
    return proposal


def _read_for_patch(worktree: Path, path: str) -> str | None:
    """Read ``path`` from ``worktree``, or return None when it cannot be read safely.

    Paths that are not clean repository-relative paths, that escape the worktree, or that
    are not decodable text are reported as missing, which makes the reconstruction refuse
    instead of reading outside the disposable tree.
    """
    from ..remediation import normalize_relative_path

    normalized = normalize_relative_path(path)
    if normalized is None:
        return None
    root = worktree.resolve()
    target = (root / normalized).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None
    try:
        return target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
