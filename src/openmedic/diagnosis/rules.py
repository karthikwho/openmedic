"""Deterministic diagnosis rules for CI/CD failure logs.

The rules in this module implement the deterministic path required by PRD FR-004 and
FR-008: they inspect ``FailureEvent.logs`` only, need no network access and no model
credential, and return either a match or nothing at all.

Two design rules govern every rule here:

1. **Precise signature, not keyword search.** A rule matches a real traceback or tool
   output shape (``ModuleNotFoundError: No module named 'requests'``) and then inspects
   the *surrounding* lines to pick the most relevant failure location, per TRD §6. A log
   that merely mentions the word "error" never matches.
2. **Quotable evidence only.** Every evidence tuple carries a line that is literally
   present in the raw log, so :class:`~openmedic.diagnosis.engine.DiagnosisEngine` can
   verify the quote against ``event.logs`` before it is allowed into a
   ``DiagnosisResult``. A rule never synthesises text: when it cannot point at a real
   line, it returns ``None`` instead of guessing.

Confidence is expressed as a bounded, hand-calibrated score, not as the probability
that a fix works (API_CONTRACTS.md §3).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..domain.contracts import FailureEvent
from ..domain.enums import FailureType, RecommendedAction, RiskLevel

__all__ = [
    "BuildOrConfigRule",
    "DependencyResolutionRule",
    "DiagnosisRule",
    "MissingModuleRule",
    "RuleMatch",
    "SyntaxOrImportRule",
    "TestFailureRule",
    "UnknownRule",
    "default_rules",
]

#: A ``(1-based line number, raw line text)`` pair.
LineHit = tuple[int, str]

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _bounded(value: float) -> float:
    """Clamp ``value`` into the contract's ``[0.0, 1.0]`` confidence range."""
    return min(max(value, 0.0), 1.0)


def _hits(lines: list[str], pattern: re.Pattern[str]) -> list[tuple[int, re.Match[str]]]:
    """Return ``(line number, match)`` for every line of ``lines`` that matches."""
    found: list[tuple[int, re.Match[str]]] = []
    for number, line in enumerate(lines, start=1):
        match = pattern.search(line)
        if match is not None:
            found.append((number, match))
    return found


def _quote(line: str) -> str:
    """Return ``line`` without surrounding whitespace.

    Whitespace stripping is safe here: the result is always a substring of the original
    line, which is itself a substring of ``event.logs``, so the engine's verbatim
    verification still succeeds.
    """
    return line.strip()


def _above(
    lines: list[str], number: int, pattern: re.Pattern[str], window: int = 3
) -> LineHit | None:
    """Return the closest matching line strictly above 1-based ``number``."""
    lowest = max(0, number - 1 - window)
    for index in range(number - 2, lowest - 1, -1):
        match = pattern.search(lines[index])
        if match is not None:
            return (index + 1, lines[index])
    return None


def _below(
    lines: list[str], number: int, pattern: re.Pattern[str], window: int = 3
) -> LineHit | None:
    """Return the closest matching line strictly below 1-based ``number``."""
    highest = min(len(lines) - 1, number - 1 + window)
    for index in range(number, highest + 1):
        match = pattern.search(lines[index])
        if match is not None:
            return (index + 1, lines[index])
    return None


def _first_code_line(lines: list[str], start: int, end: int) -> LineHit | None:
    """Return the first source line strictly between 1-based ``start`` and ``end``.

    Blank lines, interpreter caret markers and traceback frame headers are skipped, so
    the caller gets the offending source statement rather than the traceback furniture
    around it.
    """
    highest = min(end, len(lines) + 1)
    for number in range(start + 1, highest):
        text = lines[number - 1]
        if not text.strip() or _CARET_RE.search(text) or _TRACEBACK_FRAME_RE.search(text):
            continue
        return (number, text)
    return None


def _distinct(values: Iterable[str]) -> list[str]:
    """Return ``values`` with duplicates removed, preserving first-seen order."""
    seen: list[str] = []
    for value in values:
        if value not in seen:
            seen.append(value)
    return seen


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

# -- import failures --------------------------------------------------------
_PY_EXCEPTION_LINE_RE = re.compile(
    r"^\s*(?:E\s+)?(?P<name>ModuleNotFoundError|ImportError)\s*:\s*(?P<message>.+?)\s*$"
)
_MODULE_NAMED_RE = re.compile(r"No module named ['\"](?P<module>[^'\"]+)['\"]")
_CANNOT_IMPORT_NAME_RE = re.compile(
    r"cannot import name ['\"](?P<name>[^'\"]+)['\"] from ['\"](?P<module>[^'\"]+)['\"]"
    r"(?:\s+\((?P<path>[^)]+)\))?"
)
_TRACEBACK_FRAME_RE = re.compile(
    r"^\s*File\s+[\"'](?P<path>[^\"']+)[\"'],\s+line\s+(?P<line>\d+)(?:,\s+in\s+(?P<func>.+))?$"
)
_PY_IMPORT_STATEMENT_RE = re.compile(r"^\s*(?:from\s+[.\w]+\s+import\b|import\s+[.\w]+)")
_NODE_MISSING_MODULE_RE = re.compile(r"Error:\s*Cannot find module\s+['\"](?P<module>[^'\"]+)['\"]")
_NODE_REQUIRE_STACK_RE = re.compile(
    r"^\s*(?:Require stack:|at\s+Object\.<anonymous>|at\s+\S+\s+\(node:)"
)

#: Installed-environment directories. A module resolved from one of these is third
#: party; anywhere else it is project source.
_SITE_PACKAGES_RE = re.compile(r"[\\/](?:site|dist)-packages[\\/]")


def _module_is_project_source(path: str) -> bool:
    """Return whether ``path`` locates a module in project source.

    CPython prints the resolving module's path next to ``cannot import name`` only when
    the module itself was found, so a path that is not inside an installed environment
    is positive evidence that the *code* is wrong rather than the environment.
    """
    return _SITE_PACKAGES_RE.search(path) is None


def _pytest_collection_is_internal(lines: list[str], module: str) -> tuple[str, int] | None:
    """Return the pytest collecting frame when ``module`` is the project's own package.

    pytest prints ``ERROR collecting <path>`` for each file it could not import. When the
    missing module's first dotted segment is that file's own top-level package, the import
    lives in the project under test (``tests.helpers.fixtures`` collected from
    ``tests/test_smoke.py``), not in a distribution: the suite could not collect because
    project code does not resolve. A third-party package (``requests`` collected from
    ``tests/test_api.py``) has no such relationship and is left to DEP-001.
    """
    top_level = module.split(".", 1)[0]
    for number, match in _hits(lines, _PYTEST_COLLECTING_RE):
        collected = match.group("path").replace("\\", "/")
        first = collected.split("/", 1)[0]
        if first and first == top_level:
            return (collected, number)
    return None


# -- dependency resolution ---------------------------------------------------
_PIP_NO_MATCHING_DIST_RE = re.compile(
    r"^ERROR:\s*No matching distribution found for\s+(?P<pkg>.+?)\s*$"
)
_PIP_NO_VERSION_RE = re.compile(
    r"^ERROR:\s*Could not find a version that satisfies the requirement\s+(?P<req>\S+)"
)
_PIP_CONFLICT_RE = re.compile(
    r"^ERROR:\s*(?P<detail>.+?because these package versions have conflicting dependencies\.)$"
)
#: npm's message prefix. npm v6 prints ``npm ERR!``; npm v7+ prints ``npm error``. Both
#: are accepted everywhere npm output is read, so a log captured with one major version
#: is not silently invisible to a rule authored against the other.
_NPM_PREFIX = r"npm\s+(?:ERR!|error)"
_NPM_RESOLVE_RE = re.compile(
    rf"^{_NPM_PREFIX}\s*(?:code\s+ERESOLVE|ERESOLVE\s+could not resolve"
    r"|Could not resolve dependency:.*)$"
)
_NPM_404_RE = re.compile(rf"^{_NPM_PREFIX}\s*404\s+(?P<detail>.+?)\s*$")
_INSTALL_COMMAND_RE = re.compile(
    r"^\s*(?:\$\s*)?(?:python3?\s+-m\s+)?(?:pip|pip3|npm|yarn|pnpm|poetry|uv)\s+(?:install|add|ci|sync)\b"
)

# -- syntax -----------------------------------------------------------------
_SYNTAX_EXCEPTION_RE = re.compile(
    r"^\s*(?:E\s+)?(?P<name>SyntaxError|IndentationError|TabError)\s*:\s*(?P<message>.+?)\s*$"
)
_SYNTAX_FRAME_RE = re.compile(r"^\s*File\s+[\"'](?P<path>[^\"']+)[\"'],\s+line\s+(?P<line>\d+)\s*$")
_CARET_RE = re.compile(r"^\s*\^")

# -- tests ------------------------------------------------------------------
_PYTEST_FAILURE_SECTION_RE = re.compile(r"^=+\s*FAILURES\s*=+$")
_PYTEST_COLLECTING_RE = re.compile(r"^\s*_*\s*ERROR collecting\s+(?P<path>\S+)\s*_*\s*$")
_PYTEST_COLLECTED_TALLY_RE = re.compile(
    r"^collected\s+(?P<count>\d+)\s+items?(?:\s*/\s*(?P<errors>\d+)\s+errors?)?\s*$"
)
_PYTEST_SUMMARY_SECTION_RE = re.compile(
    r"^=+\s*(?:short test summary info|short test summary)\s*=+$"
)
_PYTEST_TALLY_RE = re.compile(r"^=+\s*(?P<failed>\d+)\s+failed(?P<tail>.*?)\s*=+$")
_PYTEST_FAILED_LINE_RE = re.compile(r"^FAILED\s+(?P<nodeid>\S+)(?:\s+-\s+(?P<err>.+))?$")
_PYTEST_DETAIL_RE = re.compile(r"^E\s+(?P<body>.+)$")
_JEST_FAIL_MARK_RE = re.compile(r"^\s*[\u2715\u2717\u00d7]\s+(?P<name>.+?)\s*\(\d+\s*ms\)\s*$")
_JEST_DESCRIBE_RE = re.compile(r"^\s*[\u25cf\u2022]\s+(?P<suite>.+?)\s*\u203a\s*(?P<name>.+?)\s*$")
_JEST_TALLY_RE = re.compile(r"^\s*Tests:\s+(?P<summary>.+?)\s*$")
_MOCHA_FAILURE_RE = re.compile(r"^\s*(?P<index>\d+)\)\s+(?P<name>.+?)\s*$")
_MOCHA_TALLY_RE = re.compile(r"^\s*(?P<kind>passing|failing|pending)\s*(?P<count>\d+)?$")
_ASSERTION_LINE_RE = re.compile(
    r"(?:\bassert\b|\bAssertionError\b|\bAssertion failed\b|expect\(\s*received\s*\)\.|toBe\(|"
    r"should\s+(?:be|equal))"
)
_EXPECT_MATCHER_RE = re.compile(r"expect\(\s*received\s*\)\.(?P<matcher>\w+)\((?P<expected>.+)\)")

# -- build / config ---------------------------------------------------------
#: Docker's failure lines are emitted bare by the classic builder and prefixed with a
#: BuildKit step number (``#3 ERROR: ...``) or a progress timestamp (``3.412 ERROR: ...``)
#: by BuildKit. The prefix is optional so both builders are read.
_DOCKER_BUILDKIT_PREFIX = r"(?:#\d+|[\d.]+)\s+"
_DOCKER_FAILED_STEP_RE = re.compile(r"^ERROR\s+\[(?P<step>\d+)/(?P<total>\d+)\]\s+(?P<verb>[A-Z]+)")
_DOCKER_BUILDKIT_STEP_RE = re.compile(
    r"^#\d+\s+\[(?P<step>\d+)/(?P<total>\d+)\]\s+(?P<verb>[A-Z]+)"
)
_DOCKER_NONZERO_RE = re.compile(
    r"^.*The command\s+(?P<quote>['\"])?(?P<cmd>[^'\"]+)(?P=quote)?"
    r"\s+returned a non-zero code:\s*(?P<code>\d+)"
)
_DOCKER_SOLVE_RE = re.compile(
    rf"^{_DOCKER_BUILDKIT_PREFIX}?ERROR:\s*failed to solve:\s*(?P<detail>.+?)\s*$"
)
_NPM_ERRCODE_RE = re.compile(rf"^{_NPM_PREFIX}\s*code\s+(?P<code>[A-Z_]+)$")
_NPM_FAILED_AT_RE = re.compile(rf"^{_NPM_PREFIX}\s*failed at the\s+(?P<location>.+?)\s*$")
#: Resolver-level npm codes. These describe an unsatisfiable dependency set, which is
#: DEP-002's signature; the build rule must not outvote it on the same line.
_NPM_RESOLVER_CODES = frozenset({"ERESOLVE", "E404"})
_PIP_WHEEL_RE = re.compile(r"^ERROR:\s*Failed building wheel for\s+(?P<pkg>\S+)")
_PIP_METADATA_RE = re.compile(r"^\s*error:\s*metadata-generation-failed")
_GCC_ERROR_RE = re.compile(r"^(?P<compiler>gcc|g\+\+|clang|cc)\s*:\s*error:")
_LINKER_ERROR_RE = re.compile(r"^(?:collect2:|cargo)link.*(?:error|failed)")
_TS_ERROR_RE = re.compile(r"^(?:error\s*)?TS\d+:\s*(?P<detail>.+?)\s*$")
_WEBPACK_ERROR_RE = re.compile(r"^ERROR in\s+(?P<file>\S+)")
_MAKE_ERROR_RE = re.compile(
    r"^make(?:\[\d+\])?:\s*\*\*\*\s*\[(?P<target>[^\]]+)\]\s*Error\s+(?P<code>\d+)"
)
_GRADLE_ERROR_RE = re.compile(r"^(?:BUILD FAILURE|FAILURE:\s*Build failed.*)$")
_RUST_ERROR_RE = re.compile(r"^error\[E\d+\]:\s*(?P<detail>.+)$")
_CONFIG_ERROR_RE = re.compile(
    r"^(?:Error:\s*)?(?:Cannot find|Could not find|Failed to (?:load|read|parse))\s+"
    r"(?:the\s+)?(?:config(?:uration)?\s+)?(?:file|module|settings)"
)
#: A tool stating that a required environment variable is unset. The variable name is
#: captured because the name is the actionable part of the message.
_MISSING_ENV_VAR_RE = re.compile(
    r"(?:required|needed|expected)\s+environment\s+variable\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+is\s+not\s+set",
    re.IGNORECASE,
)
#: A YAML parser rejecting a document, quoting the line it stopped on.
_YAML_SYNTAX_RE = re.compile(r"^yaml:\s*line\s+(?P<line>\d+):\s*(?P<detail>.+?)\s*$")
#: GitHub Actions naming the workflow definition it could not parse.
_WORKFLOW_FILE_RE = re.compile(r"^Invalid workflow file:\s*['\"](?P<path>[^'\"]+)['\"]\s*$")

# -- unknown ----------------------------------------------------------------
_GENERIC_ERROR_RE = re.compile(r"\b(?:error|exception|traceback|fatal)\b", re.IGNORECASE)
_EXIT_CODE_RE = re.compile(
    r"(?:exit(?:ed with)? code\s+(?P<code>\d+)|returned a non-zero code:\s*(?P<code2>\d+))"
)
_GITHUB_ERROR_RE = re.compile(r"^##\[(?:error|warning)\]")


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """The outcome of a rule inspecting one log.

    ``evidence`` holds ``(source_label, verbatim_quote, explanation)`` triples. The
    quote is raw log text: the engine verifies it against ``FailureEvent.logs`` and
    refuses to publish an unverified, non-inferred quote.
    """

    rule_id: str
    rule_version: str
    failure_type: FailureType
    probable_cause: str
    confidence: float
    risk_level: RiskLevel
    recommended_action: RecommendedAction
    requires_human_review: bool
    limitations: list[str]
    evidence: list[tuple[str, str, str]]


@dataclass(frozen=True, slots=True)
class DiagnosisRule:
    """One deterministic rule.

    Concrete rules subclass this and implement :meth:`match`. The four fields below
    are the rule identity reported through ``DiagnosisResult.rule_id`` /
    ``rule_version`` so a diagnosis is always attributable to a versioned rule.
    """

    rule_id: str
    rule_version: str
    failure_type: FailureType
    description: str

    def match(self, event: FailureEvent, lines: list[str]) -> RuleMatch | None:
        """Return a :class:`RuleMatch` for ``event``, or ``None`` when the signature is absent.

        Implementations must be pure: identical ``event`` and ``lines`` always produce
        an identical match, with no clock, randomness, network, or shared state.
        """
        msg = "concrete rules must implement match()"
        raise NotImplementedError(msg)


def _match(
    rule: DiagnosisRule,
    *,
    cause: str,
    confidence: float,
    evidence: list[tuple[str, str, str]],
    limitations: list[str],
    risk: RiskLevel,
    action: RecommendedAction,
    review: bool,
) -> RuleMatch:
    """Build a :class:`RuleMatch` bound to ``rule``'s identity."""
    return RuleMatch(
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        failure_type=rule.failure_type,
        probable_cause=cause,
        confidence=_bounded(confidence),
        risk_level=risk,
        recommended_action=action,
        requires_human_review=review,
        limitations=_distinct(limitations),
        evidence=evidence,
    )


def _line_evidence(number: int, line: str, explanation: str) -> tuple[str, str, str]:
    """Return a ``(source_label, quote, explanation)`` triple for a raw line."""
    return (f"logs:{number}", _quote(line), explanation)


def _missing_module_count(lines: list[str]) -> int:
    """Return the number of distinct modules reported missing across ``lines``."""
    modules = [
        m.group("module")
        for _, m in _hits(lines, _PY_EXCEPTION_LINE_RE)
        for m in [_MODULE_NAMED_RE.search(m.group("message"))]
        if m
    ]
    modules.extend(m.group("module") for _, m in _hits(lines, _NODE_MISSING_MODULE_RE))
    return len(_distinct(modules))


class MissingModuleRule(DiagnosisRule):
    """DEP-001: an imported module is absent from the job environment.

    Matches the terminal ``ModuleNotFoundError`` / ``ImportError`` line of a Python
    traceback, or Node's ``Error: Cannot find module '<pkg>'``. The traceback frame and
    the offending ``import`` statement are pulled from the surrounding lines so the
    evidence points at the *failing import*, not merely at the interpreter's summary.

    Two import-shaped cases are deliberately left to other rules, because calling either
    one a missing dependency would name a package nobody has to install: a module that
    resolves *inside the project* (a wrong symbol in project source, owned by SYN-001),
    and a project module that fails to resolve while pytest is collecting (the suite did
    not collect, owned by TEST-001).
    """

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(
            rule_id="DEP-001",
            rule_version="1.0.0",
            failure_type=FailureType.DEPENDENCY_ERROR,
            description=(
                "A module imported by the code is not installed "
                "(ModuleNotFoundError/ImportError/Cannot find module)."
            ),
        )

    def match(self, event: FailureEvent, lines: list[str]) -> RuleMatch | None:
        """Match a missing-module import failure."""
        python = self._python_signal(lines)
        node = self._node_signal(lines)
        signal = python or node
        if signal is None:
            return None
        cause, confidence, evidence, limitations = signal
        missing = _missing_module_count(lines)
        if missing > 1:
            # Several distinct missing modules point at a broken environment or a
            # half-applied install step, not at a single wrong requirement line.
            confidence -= 0.05 * (missing - 1)
            limitations.append(
                f"{missing} distinct modules are reported missing; the environment is "
                "broken rather than a single package being absent."
            )
        return _match(
            self,
            cause=cause,
            confidence=confidence,
            evidence=evidence,
            limitations=limitations,
            risk=RiskLevel.LOW,
            action=RecommendedAction.FIX_DEPENDENCY,
            review=False,
        )

    def _python_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        hits = _hits(lines, _PY_EXCEPTION_LINE_RE)
        if not hits:
            return None
        # The last exception line is the terminal, unhandled one.
        number, match = hits[-1]
        message = match.group("message")
        named = _MODULE_NAMED_RE.search(message)
        cannot = _CANNOT_IMPORT_NAME_RE.search(message)
        module = named.group("module") if named else (cannot.group("module") if cannot else None)
        if module is not None and _pytest_collection_is_internal(lines, module) is not None:
            # The unresolved module is the project's own package, reported while pytest
            # was collecting. The suite failed to collect; TEST-001 owns that signature,
            # and calling it a missing dependency would name a package nobody has to
            # install.
            return None
        if cannot is not None:
            path = cannot.group("path")
            if path is not None and _module_is_project_source(path):
                # The module was found inside the project, so the environment is fine
                # and the code is wrong. SYN-001 owns that signature.
                return None
        limitations = [
            "The rule reports which module failed to import; it does not verify whether "
            "the declared requirements actually provide it."
        ]
        if named is not None:
            cause = (
                f"The interpreter cannot import '{module}': the module is not installed "
                "in the job environment, so every step that imports it fails."
            )
        elif cannot is not None:
            cause = (
                f"'{module}' does not export '{cannot.group('name')}', so the import "
                "fails; this is usually a version mismatch or a renamed symbol."
            )
            limitations.append(
                "A missing symbol inside an installed package can be caused by either a "
                "wrong version pin or a breaking rename; the log alone cannot decide."
            )
        else:
            module = None
            cause = (
                "The interpreter aborted while importing a module "
                f"({match.group('name')}: {message}); the exact missing dependency is "
                "not identifiable from this line alone."
            )
            limitations.append(
                "The exception message does not name a module, so the failing dependency "
                "cannot be pinned to a single package."
            )

        confidence = 0.92
        evidence = [
            _line_evidence(
                number, lines[number - 1], "Terminal exception raised by the interpreter."
            )
        ]
        frame = _above(lines, number, _TRACEBACK_FRAME_RE, window=8)
        if frame is not None:
            confidence += 0.03
            evidence.append(
                _line_evidence(frame[0], frame[1], "Frame that performed the failing import.")
            )
            statement = _below(lines, frame[0], _PY_IMPORT_STATEMENT_RE, window=6)
            if statement is not None:
                confidence += 0.02
                evidence.append(
                    _line_evidence(
                        statement[0],
                        statement[1],
                        "Import statement whose target is unavailable at runtime.",
                    )
                )
        else:
            limitations.append(
                "No traceback frame is present, so the importing file could not be "
                "located for quote verification."
            )
        return (cause, min(confidence, 0.95), evidence, limitations)

    def _node_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        hits = _hits(lines, _NODE_MISSING_MODULE_RE)
        hits = [
            (number, match)
            for number, match in hits
            if not match.group("module").startswith((".", "/"))
        ]
        if not hits:
            return None
        number, match = hits[-1]
        module = match.group("module")
        confidence = 0.86
        evidence = [
            _line_evidence(
                number, lines[number - 1], "Node reported the package it could not resolve."
            )
        ]
        limitations = [
            "Node resolution errors can be caused by a missing dependency, a stale "
            "node_modules cache, or a private registry credential; the log alone cannot "
            "distinguish them."
        ]
        stack = _below(lines, number, _NODE_REQUIRE_STACK_RE, window=4)
        if stack is not None:
            confidence += 0.03
            evidence.append(
                _line_evidence(
                    stack[0],
                    stack[1],
                    "Require stack showing where the resolution failed.",
                )
            )
        cause = (
            f"Node cannot resolve the package '{module}' from the require path, so the "
            "process exits before running; the package is absent or not installed."
        )
        return (cause, confidence, evidence, limitations)


class DependencyResolutionRule(DiagnosisRule):
    """DEP-002: the resolver could not produce an installable dependency set.

    Matches pip resolver errors and npm ``ERESOLVE``/404 shapes, and quotes the install
    command that invoked the resolver when it is visible in the surrounding lines.
    """

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(
            rule_id="DEP-002",
            rule_version="1.0.0",
            failure_type=FailureType.DEPENDENCY_ERROR,
            description=(
                "Dependency resolver or install step cannot satisfy the declared requirements."
            ),
        )

    def match(self, event: FailureEvent, lines: list[str]) -> RuleMatch | None:
        """Match a pip or npm dependency resolution failure."""
        candidates: list[tuple[float, str, list[tuple[str, str, str]], list[str]]] = []
        for finder in (self._pip_signal, self._npm_signal):
            signal = finder(lines)
            if signal is not None:
                candidates.append(signal)
        if not candidates:
            return None
        # Strongest (highest-confidence) signal wins; ties fall back to the first finder.
        candidates.sort(key=lambda item: -item[0])
        confidence, cause, evidence, limitations = candidates[0]
        return _match(
            self,
            cause=cause,
            confidence=confidence,
            evidence=evidence,
            limitations=limitations,
            risk=RiskLevel.MEDIUM,
            action=RecommendedAction.FIX_DEPENDENCY,
            review=True,
        )

    def _pip_signal(
        self, lines: list[str]
    ) -> tuple[float, str, list[tuple[str, str, str]], list[str]] | None:
        for pattern, kind in (
            (_PIP_NO_VERSION_RE, "no-version"),
            (_PIP_CONFLICT_RE, "conflict"),
            (_PIP_NO_MATCHING_DIST_RE, "no-distribution"),
        ):
            hits = _hits(lines, pattern)
            if not hits:
                continue
            number, match = hits[0]
            confidence = 0.80
            evidence = [
                _line_evidence(
                    number,
                    lines[number - 1],
                    "Resolver reported that no installable version exists.",
                )
            ]
            limitations = [
                "The rule reports the resolver's verdict; it does not re-resolve the "
                "dependency graph, so a different index or platform may still succeed."
            ]
            if kind == "no-version":
                requirement = match.group("req")
                cause = (
                    f"The resolver cannot find any published version of '{requirement}' "
                    "that satisfies the declared requirements, so installation stops "
                    "before any package is written."
                )
                confidence += 0.05
            elif kind == "conflict":
                cause = (
                    f"The declared requirements are mutually unsatisfiable: {match.group('detail')}"
                )
                confidence += 0.05
                limitations.append(
                    "A conflict can be resolved by relaxing or pinning several packages; "
                    "more than one requirement change is usually involved."
                )
            else:
                cause = (
                    f"No distribution of '{match.group('pkg')}' exists for the current "
                    "Python version or platform, so pip has nothing to install."
                )
                limitations.append(
                    "A missing distribution can be platform-specific; the rule does not "
                    "check whether wheels exist for another Python version."
                )
            command = _above(lines, number, _INSTALL_COMMAND_RE, window=6)
            if command is not None:
                confidence += 0.05
                evidence.append(
                    _line_evidence(
                        command[0],
                        command[1],
                        "Install command whose resolver failed.",
                    )
                )
            return (confidence, cause, evidence, limitations)
        return None

    def _npm_signal(
        self, lines: list[str]
    ) -> tuple[float, str, list[tuple[str, str, str]], list[str]] | None:
        resolve = _hits(lines, _NPM_RESOLVE_RE)
        not_found = _hits(lines, _NPM_404_RE)
        if not resolve and not not_found:
            return None
        number, _ = (resolve or not_found)[0]
        confidence = 0.80
        evidence = [
            _line_evidence(
                number, lines[number - 1], "npm reported an unsatisfiable dependency set."
            )
        ]
        limitations = [
            "npm resolver errors can come from a conflicting peer dependency, a stale "
            "lock file, or an unavailable registry entry; the log alone cannot decide."
        ]
        if resolve:
            cause = (
                "npm's dependency resolver cannot satisfy the peer/version constraints "
                "of the manifest, so no dependency tree can be produced."
            )
        else:
            cause = (
                "npm received 404 Not Found for a package it was asked to install, so "
                "the dependency cannot be fetched from the configured registry."
            )
            confidence += 0.05
        command = _above(lines, number, _INSTALL_COMMAND_RE, window=6)
        if command is not None:
            confidence += 0.05
            evidence.append(
                _line_evidence(command[0], command[1], "Install command whose resolver failed.")
            )
        return (confidence, cause, evidence, limitations)


class SyntaxOrImportRule(DiagnosisRule):
    """SYN-001: the file cannot be parsed or its own code-level import is broken.

    Matches ``SyntaxError``/``IndentationError``/``TabError``, Node's
    ``Cannot find module './relative'``, and Python's ``cannot import name 'x' from
    'pkg'`` when ``pkg`` resolves inside the project rather than in an installed
    environment. A broken *relative* path or a wrong symbol in project source is a code
    defect, not a missing dependency, which is why both land here instead of on DEP-001.
    """

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(
            rule_id="SYN-001",
            rule_version="1.0.0",
            failure_type=FailureType.SYNTAX_OR_IMPORT_ERROR,
            description=(
                "Source or test file cannot be parsed, or a code-level import path is wrong."
            ),
        )

    def match(self, event: FailureEvent, lines: list[str]) -> RuleMatch | None:
        """Match a source or test file that cannot be parsed or imported."""
        candidates: list[tuple[float, str, list[tuple[str, str, str]], list[str]]] = []
        for finder in (self._python_signal, self._import_signal, self._node_signal):
            signal = finder(lines)
            if signal is not None:
                candidates.append(signal)
        if not candidates:
            return None
        candidates.sort(key=lambda item: -item[0])
        confidence, cause, evidence, limitations = candidates[0]
        return _match(
            self,
            cause=cause,
            confidence=confidence,
            evidence=evidence,
            limitations=limitations,
            risk=RiskLevel.LOW,
            action=RecommendedAction.FIX_SYNTAX_OR_IMPORT,
            review=False,
        )

    def _python_signal(
        self, lines: list[str]
    ) -> tuple[float, str, list[tuple[str, str, str]], list[str]] | None:
        hits = _hits(lines, _SYNTAX_EXCEPTION_RE)
        if not hits:
            return None
        number, match = hits[-1]
        kind = match.group("name")
        message = match.group("message")
        frame = _above(lines, number, _SYNTAX_FRAME_RE, window=8)
        confidence = 0.92
        evidence = [
            _line_evidence(
                number, lines[number - 1], "Parser error stopping the file from being compiled."
            )
        ]
        limitations = [
            "The rule reports the parser verdict and the location it printed; it does not "
            "propose an edit, and an edited file must be re-validated."
        ]
        if frame is not None:
            frame_match = _SYNTAX_FRAME_RE.search(frame[1])
            location = (
                f"{frame_match.group('path')}:{frame_match.group('line')}"
                if frame_match is not None
                else "an unlocated line"
            )
            evidence.append(_line_evidence(frame[0], frame[1], "Location reported by the parser."))
            confidence += 0.02
            statement = _first_code_line(lines, frame[0], number)
            if statement is not None:
                confidence += 0.02
                evidence.append(
                    _line_evidence(statement[0], statement[1], "Source line the parser rejected.")
                )
        else:
            location = "an unlocated line"
            limitations.append(
                "No file/line frame precedes the parser error, so the offending file could "
                "not be located from the log."
            )
        cause = f"The Python parser rejects the file at {location} with {kind}: {message}."
        return (min(confidence, 0.95), cause, evidence, limitations)

    def _import_signal(
        self, lines: list[str]
    ) -> tuple[float, str, list[tuple[str, str, str]], list[str]] | None:
        """Match a wrong symbol imported from a module that exists in this project.

        ``ImportError: cannot import name 'x' from 'pkg' (/path/pkg/__init__.py)`` proves
        the module was found, because CPython prints the path only when resolution
        succeeded. A path inside an installed environment means a version mismatch and is
        left to DEP-001; a path in project source means the code names a symbol the module
        does not export, which is a code defect like a syntax error.
        """
        for number, match in reversed(_hits(lines, _CANNOT_IMPORT_NAME_RE)):
            path = match.group("path")
            if path is None or not _module_is_project_source(path):
                continue
            module = match.group("module")
            name = match.group("name")
            confidence = 0.90
            evidence = [
                _line_evidence(
                    number,
                    lines[number - 1],
                    "Import that resolved the module but not the symbol it names.",
                )
            ]
            limitations = [
                "The module exists in project source, so the defect is the imported name "
                "rather than the environment; the rule reports the name and does not "
                "guess its replacement.",
            ]
            frame = _above(lines, number, _TRACEBACK_FRAME_RE, window=8)
            if frame is not None:
                confidence += 0.02
                evidence.append(
                    _line_evidence(frame[0], frame[1], "Frame that performed the failing import.")
                )
                statement = _below(lines, frame[0], _PY_IMPORT_STATEMENT_RE, window=6)
                if statement is not None:
                    confidence += 0.02
                    evidence.append(
                        _line_evidence(
                            statement[0],
                            statement[1],
                            "Import statement whose symbol does not exist.",
                        )
                    )
            else:
                limitations.append(
                    "No traceback frame precedes the import error, so the importing file "
                    "could not be located from the log."
                )
            cause = (
                f"'{module}' is present in this project at {path}, but it does not export "
                f"'{name}', so the import fails; the code names a symbol the module does "
                "not define."
            )
            return (min(confidence, 0.95), cause, evidence, limitations)
        return None

    def _node_signal(
        self, lines: list[str]
    ) -> tuple[float, str, list[tuple[str, str, str]], list[str]] | None:
        hits = [
            (number, match)
            for number, match in _hits(lines, _NODE_MISSING_MODULE_RE)
            if match.group("module").startswith((".", "/"))
        ]
        if not hits:
            return None
        number, match = hits[-1]
        module = match.group("module")
        confidence = 0.85
        evidence = [
            _line_evidence(
                number, lines[number - 1], "Node resolved the entry point but not a local import."
            )
        ]
        limitations = [
            "A missing relative module can mean a wrong path or a file that failed to "
            "build; the rule does not inspect the repository."
        ]
        cause = (
            f"Node resolves the entry point but cannot find the local module '{module}'; "
            "the import path or the file it points at is missing or wrong."
        )
        return (confidence, cause, evidence, limitations)


class TestFailureRule(DiagnosisRule):
    """TEST-001: the suite ran, or tried to, and it did not pass.

    Matches pytest's failure section and short summary, Jest's failure marks and tally,
    and Mocha's numbered failures. Assertion detail lines are preferred over the summary
    because they carry the compared values. A test module that cannot be collected is
    also a test failure, but only when the module that failed to resolve is the project's
    own package: a missing *third-party* package during collection is left to DEP-001,
    because there the fix is an install rather than a code change.
    """

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(
            rule_id="TEST-001",
            rule_version="1.0.0",
            failure_type=FailureType.TEST_FAILURE,
            description="Test suite executed and at least one test failed an assertion.",
        )

    def match(self, event: FailureEvent, lines: list[str]) -> RuleMatch | None:
        """Match a pytest or jest test failure."""
        candidates: list[tuple[str, float, list[tuple[str, str, str]], list[str]]] = []
        for finder in (
            self._pytest_signal,
            self._pytest_collection_signal,
            self._jest_signal,
            self._mocha_signal,
        ):
            signal = finder(lines)
            if signal is not None:
                candidates.append(signal)
        if not candidates:
            return None
        # Strongest signal wins; the sort is stable, so an equally confident assertion
        # signal keeps its place ahead of a weaker one.
        candidates.sort(key=lambda item: -item[1])
        cause, confidence, evidence, limitations = candidates[0]
        return _match(
            self,
            cause=cause,
            confidence=confidence,
            evidence=evidence,
            limitations=limitations,
            risk=RiskLevel.LOW,
            action=RecommendedAction.FIX_FAILING_TEST,
            review=False,
        )

    def _common(self, evidence: list[tuple[str, str, str]]) -> list[str]:
        return [
            "The rule reports which test failed and what it observed; it cannot tell "
            "whether the test or the code under test is wrong.",
            "A single failure is not proof of a broken build; dependency and environment "
            "errors are reported by other rules.",
        ]

    def _pytest_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        failures = _hits(lines, _PYTEST_FAILURE_SECTION_RE)
        tally_lines = _hits(lines, _PYTEST_TALLY_RE)
        failed_lines = _hits(lines, _PYTEST_FAILED_LINE_RE)
        if not failures and not failed_lines:
            return None
        evidence: list[tuple[str, str, str]] = []
        limitations = self._common(evidence)
        nodeid = "the failing test"
        err = None
        if failed_lines:
            number, match = failed_lines[0]
            nodeid = match.group("nodeid")
            err = match.group("err")
            evidence.append(
                _line_evidence(
                    number, lines[number - 1], "pytest's short summary naming the failing test."
                )
            )
        if failures:
            number, _ = failures[0]
            evidence.append(
                _line_evidence(number, lines[number - 1], "Start of the failure detail section.")
            )
        # Assertion detail carries the compared values, so it outranks a bare summary.
        detail = self._nearest_assertion_detail(lines, number if failures else 0)
        if detail is None:
            detail = self._nearest_e_line(lines, number if failures else 0)
        if detail is not None:
            evidence.append(
                _line_evidence(detail[0], detail[1], "Assertion values reported by the test.")
            )
        confidence = 0.90 if detail is not None else 0.78
        if not failures and failed_lines:
            confidence -= 0.06
            limitations.append(
                "The failure detail section is missing, so only the summary line was available."
            )
        if tally_lines:
            number, match = tally_lines[0]
            evidence.append(_line_evidence(number, lines[number - 1], "pytest's final tally line."))
        if err is not None and _SYNTAX_EXCEPTION_RE.search(err):
            # Collection-time failure: another rule owns the real signature.
            confidence = min(confidence, 0.72)
            limitations.append(
                "The failure happened while collecting tests, which usually means the "
                "file itself is broken rather than the assertion."
            )
        count = len(_distinct(match.group("nodeid") for _, match in failed_lines))
        if count > 1:
            limitations.append(
                f"{count} distinct tests failed; only the first is quoted as evidence."
            )
        cause = (
            f"'{nodeid}' failed: the assertion it makes about the code under test did not "
            "hold, so the suite exits non-zero."
        )
        return (cause, confidence, evidence, limitations)

    def _pytest_collection_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        """Match a test module that could not be collected because project code is broken.

        pytest reports a collection error per file it could not import. When the module
        that failed to resolve is the project's *own* package -- determined by the
        collecting file's top-level package, see :func:`_pytest_collection_is_internal` --
        the run never reached a single test, which is a test-suite failure whose root cause
        is an unresolved project import. A missing third-party package is deliberately left
        to DEP-001, because that failure's fix is an install rather than a code change.
        """
        missing = _hits(lines, _MODULE_NAMED_RE)
        if not missing:
            return None
        for missing_number, missing_match in missing:
            module = missing_match.group("module")
            internal = _pytest_collection_is_internal(lines, module)
            if internal is None:
                continue
            collected, collecting_number = internal
            evidence = [
                _line_evidence(
                    collecting_number,
                    lines[collecting_number - 1],
                    "pytest could not collect this test module.",
                ),
                _line_evidence(
                    missing_number,
                    lines[missing_number - 1],
                    "Project module that did not resolve while collecting.",
                ),
            ]
            limitations = self._common(evidence)
            limitations.append(
                "Only the project's own package lands here; a missing third-party package "
                "during collection is reported as a dependency error, because that one "
                "has an install as its fix."
            )
            statement = _above(lines, missing_number, _PY_IMPORT_STATEMENT_RE, window=8)
            if statement is not None:
                evidence.append(
                    _line_evidence(
                        statement[0], statement[1], "Import statement collection could not resolve."
                    )
                )
            tally = _hits(lines, _PYTEST_COLLECTED_TALLY_RE)
            if tally and tally[0][1].group("errors"):
                tally_number, _ = tally[0]
                evidence.append(
                    _line_evidence(
                        tally_number,
                        lines[tally_number - 1],
                        "pytest's collection tally, showing how many tests never ran.",
                    )
                )
            cause = (
                f"pytest could not collect '{collected}' because its import of the project "
                f"module '{module}' does not resolve, so the run stops before any test "
                "executes; a suite that cannot collect is a test failure whose root cause "
                "is an unresolved project import."
            )
            return (cause, 0.88, evidence, limitations)
        return None

    def _nearest_assertion_detail(self, lines: list[str], after: int) -> LineHit | None:
        found: LineHit | None = None
        for number, match in _hits(lines, _PYTEST_DETAIL_RE):
            body = match.group("body").strip()
            if _ASSERTION_LINE_RE.search(body) or _EXPECT_MATCHER_RE.search(match.group(0)):
                found = (number, lines[number - 1])
                break
        if found is not None:
            return found
        return None if after == 0 else _below(lines, after, _PYTEST_DETAIL_RE, window=200)

    def _nearest_e_line(self, lines: list[str], after: int) -> LineHit | None:
        for number, match in _hits(lines, _PYTEST_DETAIL_RE):
            if match.group("body").strip():
                return (number, lines[number - 1])
        return None

    def _jest_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        marks = _hits(lines, _JEST_FAIL_MARK_RE)
        describes = _hits(lines, _JEST_DESCRIBE_RE)
        if not marks and not describes:
            return None
        evidence: list[tuple[str, str, str]] = []
        limitations = self._common(evidence)
        name = "the failing test"
        if marks:
            number, match = marks[0]
            name = match.group("name").strip()
            evidence.append(
                _line_evidence(number, lines[number - 1], "Jest marks this test as failed.")
            )
        suite = None
        if describes:
            number, match = describes[0]
            suite = f"{match.group('suite')} › {match.group('name')}"  # noqa: RUF001 -- Jest's own separator
            evidence.append(
                _line_evidence(number, lines[number - 1], "Jest's failing test heading.")
            )
        detail = _hits(lines, _EXPECT_MATCHER_RE)
        if detail:
            number, match = detail[0]
            evidence.append(
                _line_evidence(number, lines[number - 1], "Expectation that did not hold.")
            )
        tally = _hits(lines, _JEST_TALLY_RE)
        if tally:
            number, match = tally[0]
            evidence.append(_line_evidence(number, lines[number - 1], "Jest's tally line."))
        confidence = 0.90 if (detail or suite) else 0.75
        subject = suite if suite is not None else name
        cause = f"'{subject}' failed an expectation in the Jest run, so the suite exits non-zero."
        return (cause, confidence, evidence, limitations)

    def _mocha_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        failures = _hits(lines, _MOCHA_FAILURE_RE)
        if not failures:
            return None
        evidence: list[tuple[str, str, str]] = []
        limitations = self._common(evidence)
        number, match = failures[0]
        evidence.append(
            _line_evidence(number, lines[number - 1], "Mocha's numbered failure list entry.")
        )
        tally = _hits(lines, _MOCHA_TALLY_RE)
        if tally:
            number, match = tally[-1]
            evidence.append(_line_evidence(number, lines[number - 1], "Mocha's tally line."))
        confidence = 0.80 if tally else 0.75
        cause = f"'{match.group('name')}' failed in the Mocha run, so the suite exits non-zero."
        return (cause, confidence, evidence, limitations)


class BuildOrConfigRule(DiagnosisRule):
    """BUILD-001: the build or configuration step itself failed.

    Matches Docker build failures (classic builder and BuildKit), ``npm`` script
    failures under both its v6 (``npm ERR!``) and v7+ (``npm error``) prefixes, pip
    wheel-build failures, ``tsc``/webpack diagnostics, make/gradle/cargo errors, a
    required environment variable that is not set, and a YAML document that will not
    parse. The strongest signal in the log wins, so a build that contains several tool
    speakers is still diagnosed once, deterministically; a resolver-level npm code is
    excluded here because that signature belongs to DEP-002.
    """

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__(
            rule_id="BUILD-001",
            rule_version="1.0.0",
            failure_type=FailureType.BUILD_OR_CONFIG_ERROR,
            description="Build, compile, container, or configuration step failed.",
        )

    def match(self, event: FailureEvent, lines: list[str]) -> RuleMatch | None:
        """Match a container image or project build failure."""
        candidates: list[tuple[str, float, list[tuple[str, str, str]], list[str]]] = []
        for finder in (
            self._docker_signal,
            self._npm_signal,
            self._wheel_signal,
            self._compiler_signal,
            self._config_signal,
            self._env_var_signal,
            self._yaml_signal,
        ):
            signal = finder(lines)
            if signal is not None:
                candidates.append(signal)
        if not candidates:
            return None
        candidates.sort(key=lambda item: -item[1])
        cause, confidence, evidence, limitations = candidates[0]
        # A build failure is often reported by more than one tool. The strongest signal
        # names the cause; the runner-up contributes one supporting line so the record
        # shows what the other tool said without overriding the primary cause.
        for _, _, other_evidence, _ in candidates[1:]:
            if other_evidence and other_evidence[0] not in evidence:
                evidence.append(other_evidence[0])
        return _match(
            self,
            cause=cause,
            confidence=confidence,
            evidence=evidence,
            limitations=limitations,
            risk=RiskLevel.MEDIUM,
            action=RecommendedAction.FIX_BUILD_OR_CONFIG,
            review=True,
        )

    def _build_limitations(self) -> list[str]:
        return [
            "The rule reports the build tool's verdict and exit status; it does not "
            "reproduce the build, so an environment-specific cause stays possible.",
            "Build failures are frequently downstream of an earlier dependency or "
            "syntax failure, which is quoted separately when it is visible.",
        ]

    def _docker_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        steps = _hits(lines, _DOCKER_FAILED_STEP_RE)
        nonzero = _hits(lines, _DOCKER_NONZERO_RE)
        solved = _hits(lines, _DOCKER_SOLVE_RE)
        if not steps and not nonzero and not solved:
            return None
        evidence: list[tuple[str, str, str]] = []
        limitations = self._build_limitations()
        confidence = 0.85
        target = "the image build"
        if steps:
            number, match = steps[0]
            evidence.append(
                _line_evidence(
                    number,
                    lines[number - 1],
                    f"Build step {match.group('step')} of {match.group('total')} failed.",
                )
            )
            confidence += 0.03
            target = (
                f"the '{match.group('verb')}' instruction at step "
                f"{match.group('step')} of {match.group('total')}"
            )
        elif solved:
            # BuildKit numbers its steps separately from the failure line, so the failing
            # instruction is the nearest numbered step above the solver's complaint.
            buildkit_step = _above(lines, solved[0][0], _DOCKER_BUILDKIT_STEP_RE, window=12)
            if buildkit_step is not None:
                step_match = _DOCKER_BUILDKIT_STEP_RE.search(buildkit_step[1])
                if step_match is not None:
                    evidence.append(
                        _line_evidence(
                            buildkit_step[0],
                            buildkit_step[1],
                            f"Build step {step_match.group('step')} of "
                            f"{step_match.group('total')} failed.",
                        )
                    )
                    confidence += 0.03
                    target = (
                        f"the '{step_match.group('verb')}' instruction at step "
                        f"{step_match.group('step')} of {step_match.group('total')}"
                    )
        if nonzero:
            number, match = nonzero[0]
            evidence.append(
                _line_evidence(
                    number, lines[number - 1], "Docker reported the failing step's exit status."
                )
            )
            confidence += 0.04
            target = f"{target}, which exited with status {match.group('code')}"
        elif solved:
            number, match = solved[0]
            evidence.append(
                _line_evidence(
                    number, lines[number - 1], "Docker could not solve the build instruction."
                )
            )
            confidence += 0.04
            target = f"{target}; the solver reported: {match.group('detail')}"
        cause = (
            f"The Docker image build failed at {target}, so no image is produced and the "
            "workflow cannot run or deploy it."
        )
        return (cause, confidence, evidence, limitations)

    def _npm_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        raw_code_lines = _hits(lines, _NPM_ERRCODE_RE)
        code_lines = [
            (number, match)
            for number, match in raw_code_lines
            if match.group("code") not in _NPM_RESOLVER_CODES
        ]
        failed_at = _hits(lines, _NPM_FAILED_AT_RE)
        if not code_lines and not failed_at:
            return None
        limitations = self._build_limitations()
        if len(code_lines) < len(raw_code_lines):
            limitations.append(
                "npm also reported a resolver-level error code, which belongs to the "
                "dependency-resolution diagnosis rather than to the build step."
            )
        evidence: list[tuple[str, str, str]] = []
        confidence = 0.80
        target = "the npm script"
        if code_lines:
            number, match = code_lines[0]
            evidence.append(
                _line_evidence(number, lines[number - 1], "npm's error code for the failed script.")
            )
            confidence += 0.04
            target = f"an npm script failing with {match.group('code')}"
        if failed_at:
            number, match = failed_at[0]
            evidence.append(
                _line_evidence(
                    number,
                    lines[number - 1],
                    f"The npm script that failed ({match.group('location')}).",
                )
            )
            confidence += 0.03
        cause = f"The JavaScript package build failed at {target}, so no artifact is produced."
        return (cause, confidence, evidence, limitations)

    def _wheel_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        wheel = _hits(lines, _PIP_WHEEL_RE)
        metadata = _hits(lines, _PIP_METADATA_RE)
        if not wheel and not metadata:
            return None
        evidence: list[tuple[str, str, str]] = []
        limitations = self._build_limitations()
        limitations.append(
            "A native extension failing to build usually needs system headers; the rule "
            "does not know which package provides them."
        )
        pkg = "the package"
        if wheel:
            number, match = wheel[0]
            pkg = match.group("pkg")
            evidence.append(
                _line_evidence(
                    number, lines[number - 1], "pip could not build a wheel for this package."
                )
            )
        if metadata:
            number, _ = metadata[0]
            evidence.append(
                _line_evidence(
                    number, lines[number - 1], "The build backend failed while generating metadata."
                )
            )
        cause = f"Building '{pkg}' from source failed, so the install step cannot complete."
        return (cause, 0.85 if wheel else 0.80, evidence, limitations)

    def _compiler_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        signals = (
            (_TS_ERROR_RE, "the TypeScript compiler"),
            (_GCC_ERROR_RE, "the C/C++ compiler"),
            (_LINKER_ERROR_RE, "the linker"),
            (_WEBPACK_ERROR_RE, "the module bundler"),
            (_RUST_ERROR_RE, "the Rust compiler"),
            (_MAKE_ERROR_RE, "make"),
            (_GRADLE_ERROR_RE, "the build tool"),
        )
        found: list[tuple[int, str, str]] = []
        for pattern, speaker in signals:
            for number, _ in _hits(lines, pattern):
                found.append((number, speaker, lines[number - 1]))
        if not found:
            return None
        found.sort(key=lambda item: item[0])
        number, speaker, text = found[0]
        evidence = [
            _line_evidence(
                number, text, f"{speaker[0].upper() + speaker[1:]} rejected the sources."
            )
        ]
        limitations = self._build_limitations()
        confidence = 0.88
        lead = speaker[0].upper() + speaker[1:]
        cause = (
            f"{lead} reported a build error, so the build stops before any artifact is produced."
        )
        if len(found) > 1:
            limitations.append(
                f"{len(found)} build diagnostics are present; only the earliest is quoted."
            )
        return (cause, confidence, evidence, limitations)

    def _config_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        hits = _hits(lines, _CONFIG_ERROR_RE)
        if not hits:
            return None
        number, _ = hits[0]
        evidence = [
            _line_evidence(number, lines[number - 1], "The tool could not load its configuration.")
        ]
        limitations = self._build_limitations()
        limitations.append(
            "The rule reports that configuration failed to load; it does not validate the "
            "file's contents."
        )
        cause = (
            "The tool could not load its configuration file, so it exits before running "
            "any real work."
        )
        return (cause, 0.80, evidence, limitations)

    def _env_var_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        """Match a job that stopped because a required environment variable is unset.

        The variable name is the whole diagnosis: the job cannot proceed until it is
        defined, and the message says exactly which one. Nothing here inspects the
        workflow or repository, so a variable that is set but empty, or exported under a
        different name, cannot be told apart from one that is genuinely absent.
        """
        hits = _hits(lines, _MISSING_ENV_VAR_RE)
        if not hits:
            return None
        number, match = hits[0]
        name = match.group("name")
        evidence = [
            _line_evidence(number, lines[number - 1], f"The job requires the variable {name}.")
        ]
        limitations = self._build_limitations()
        limitations.append(
            "The rule reports the variable the tool asked for; it does not check the "
            "workflow definition, so a variable supplied by a secret or a reusable "
            "workflow cannot be confirmed from the log alone."
        )
        cause = (
            f"The job stopped because the required environment variable {name} is not "
            "set, so it exits before running any real work."
        )
        return (cause, 0.82, evidence, limitations)

    def _yaml_signal(
        self, lines: list[str]
    ) -> tuple[str, float, list[tuple[str, str, str]], list[str]] | None:
        """Match a YAML parser rejecting a document, quoting the line it stopped on.

        GitHub Actions validates workflow definitions before running anything, so a
        workflow that is not valid YAML fails with no job output at all. The parser's own
        verdict is the evidence; the file is named when the runner named it too.
        """
        hits = _hits(lines, _YAML_SYNTAX_RE)
        if not hits:
            return None
        number, match = hits[0]
        evidence = [
            _line_evidence(number, lines[number - 1], "YAML parser rejected the document here.")
        ]
        limitations = self._build_limitations()
        limitations.append(
            "The rule quotes the parser's complaint and its line number; it does not read "
            "the file, so the offending construct must be inspected by a human."
        )
        location = "the configuration document"
        workflow = _above(lines, number, _WORKFLOW_FILE_RE, window=6)
        if workflow is not None:
            workflow_match = _WORKFLOW_FILE_RE.search(workflow[1])
            if workflow_match is not None:
                location = workflow_match.group("path")
                evidence.append(
                    _line_evidence(
                        workflow[0],
                        workflow[1],
                        "The runner names the definition it could not parse.",
                    )
                )
        cause = (
            f"{location} is not valid YAML (line {match.group('line')}: "
            f"{match.group('detail')}), so nothing downstream of it can run."
        )
        return (cause, 0.85, evidence, limitations)


class UnknownRule(DiagnosisRule):
    """UNK-001: the honest fallback.

    This rule always fires, but only reaches the caller when nothing else did. It never
    names a cause: the probable cause states that no deterministic signature matched,
    and confidence stays at or below ``0.2`` so an unclassified failure is never
    confused with a diagnosed one.
    """

    __slots__ = ()

    #: Upper bound on the confidence an unclassified failure may report.
    MAX_CONFIDENCE: float = 0.2

    def __init__(self) -> None:
        super().__init__(
            rule_id="UNK-001",
            rule_version="1.0.0",
            failure_type=FailureType.UNKNOWN,
            description="Fallback for logs whose failure signature is not recognised.",
        )

    def match(self, event: FailureEvent, lines: list[str]) -> RuleMatch | None:
        """Classify the log as an unmatched failure that needs human review."""
        non_empty = [number for number, line in enumerate(lines, start=1) if line.strip()]
        limitations = [
            "No deterministic rule matched this log, so no root cause was determined.",
            "This is not a diagnosis: treat it as a classification failure that needs a "
            "human or an enriched provider run.",
        ]
        if not non_empty:
            limitations.append(
                "The event carried no log output at all, so nothing could be inspected."
            )
            return _match(
                self,
                cause="The log is empty, so no failure signature can be matched.",
                confidence=0.0,
                evidence=[],
                limitations=limitations,
                risk=RiskLevel.HIGH,
                action=RecommendedAction.INVESTIGATE_MANUALLY,
                review=True,
            )
        evidence: list[tuple[str, str, str]] = []
        quoted: list[str] = []
        confidence = 0.1
        exit_line = _hits(lines, _EXIT_CODE_RE)
        if exit_line:
            number, _ = exit_line[-1]
            evidence.append(
                _line_evidence(number, lines[number - 1], "Only the process exit status is known.")
            )
            quoted.append(_quote(lines[number - 1]))
            confidence += 0.05
        for number, line in enumerate(lines, start=1):
            if _GENERIC_ERROR_RE.search(line) and _quote(line) not in quoted:
                evidence.append(
                    _line_evidence(
                        number,
                        line,
                        "An error-shaped line exists but matches no deterministic rule.",
                    )
                )
                quoted.append(_quote(line))
                confidence += 0.05
                break
        github = _hits(lines, _GITHUB_ERROR_RE)
        if github:
            number, _ = github[-1]
            quote = _quote(lines[number - 1])
            if quote not in quoted:
                evidence.append(
                    _line_evidence(
                        number,
                        lines[number - 1],
                        "GitHub Actions reported a step-level error.",
                    )
                )
        return _match(
            self,
            cause=(
                "No deterministic rule matched the available log output, so the failure "
                "signature is unrecognised and no root cause is claimed."
            ),
            confidence=min(confidence, self.MAX_CONFIDENCE),
            evidence=evidence[:3],
            limitations=limitations,
            risk=RiskLevel.MEDIUM,
            action=RecommendedAction.INVESTIGATE_MANUALLY,
            review=True,
        )


def default_rules() -> list[DiagnosisRule]:
    """Return the built-in rule set in evaluation order.

    The list is rebuilt per call so a caller can safely mutate the result; rules
    themselves hold no state.
    """
    return [
        MissingModuleRule(),
        DependencyResolutionRule(),
        SyntaxOrImportRule(),
        TestFailureRule(),
        BuildOrConfigRule(),
        UnknownRule(),
    ]
