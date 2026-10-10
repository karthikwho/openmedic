"""Rule boundary tests: signatures a rule must *not* claim.

Every test here guards a boundary that a benchmark label exposed, written against an
inline log so the boundary itself -- rather than a fixture's incidental text -- is what
is asserted. The positive side of each boundary lives in ``test_engine.py``'s committed
classification table.
"""

from __future__ import annotations

import pytest

from openmedic.diagnosis.engine import DiagnosisEngine
from openmedic.domain.contracts import DiagnosisResult
from openmedic.domain.enums import FailureType
from openmedic.ingestion import ingest_log_text


def _diagnose(log: str) -> DiagnosisResult:
    """Diagnose ``log`` through the production engine, offline."""
    event = ingest_log_text(log, repository="acme/app", run_id="1")
    return DiagnosisEngine().diagnose(event)


_NO_PATH_SYMBOL_ERROR = """\
Traceback (most recent call last):
  File "/home/runner/work/app/app/src/service.py", line 12, in <module>
    from app import create_app
ImportError: cannot import name 'create_app' from 'app'
Error: Process completed with exit code 1.
"""

_PROJECT_SOURCE_SYMBOL_ERROR = """\
Traceback (most recent call last):
  File "/home/runner/work/app/app/src/service.py", line 12, in <module>
    from app import create_app
ImportError: cannot import name 'create_app' from 'app' (/home/runner/work/app/app/src/app/__init__.py)
Error: Process completed with exit code 1.
"""

_INSTALLED_SOURCE_SYMBOL_ERROR = """\
Traceback (most recent call last):
  File "/home/runner/work/app/app/src/client.py", line 3, in <module>
    from requests.adapters import HTTPAdapter2
ImportError: cannot import name 'HTTPAdapter2' from 'requests.adapters' (/opt/hostedtoolcache/Python/3.12.3/lib/python3.12/site-packages/requests/adapters.py)
Error: Process completed with exit code 1.
"""


def _collection_log(module: str, test_file: str) -> str:
    return f"""\
Run actions/checkout@v4
$ python -m pytest -q
============================= test session starts ==============================
platform linux -- Python 3.12.4, pytest-8.2.2, pluggy-1.5.0
collected 0 items / 1 error

==================================== ERRORS ====================================
ERROR collecting {test_file}
ImportError while importing test module '/home/runner/work/app/app/{test_file}'.
{test_file}:2: in <module>
    import {module}
E   ModuleNotFoundError: No module named '{module}'
!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
Error: Process completed with exit code 1.
"""


@pytest.mark.parametrize(
    ("log", "rule_id", "failure_type"),
    (
        # The module resolved, so the environment is fine and the code is wrong. The
        # installed-environment variant stays a dependency problem: there the fix is a
        # version pin, not an edit.
        (_PROJECT_SOURCE_SYMBOL_ERROR, "SYN-001", FailureType.SYNTAX_OR_IMPORT_ERROR),
        (_INSTALLED_SOURCE_SYMBOL_ERROR, "DEP-001", FailureType.DEPENDENCY_ERROR),
        # With no resolving path at all there is no evidence either way, so the
        # conservative dependency reading is kept.
        (_NO_PATH_SYMBOL_ERROR, "DEP-001", FailureType.DEPENDENCY_ERROR),
        # The missing module is the suite's own top-level package, so the suite did not
        # collect; a missing third-party package keeps the dependency diagnosis, because
        # there the repair is an install.
        (
            _collection_log("tests.helpers.factories", "tests/test_billing.py"),
            "TEST-001",
            FailureType.TEST_FAILURE,
        ),
        (
            _collection_log("requests", "tests/test_api.py"),
            "DEP-001",
            FailureType.DEPENDENCY_ERROR,
        ),
    ),
    ids=(
        "project-source-symbol",
        "installed-package-symbol",
        "symbol-without-path",
        "collection-internal-package",
        "collection-third-party-package",
    ),
)
def test_import_boundaries(log: str, rule_id: str, failure_type: FailureType) -> None:
    """An import-shaped log lands on the rule that owns its real cause."""
    result = _diagnose(log)

    assert result.rule_id == rule_id
    assert result.failure_type is failure_type


_NPM_V6_RESOLVE = """\
Run actions/checkout@v4
$ npm install
npm ERR! code ERESOLVE
npm ERR! ERESOLVE unable to resolve dependency tree
npm ERR! peer react@"^18.0.0" from acme-ui@1.0.0
npm ERR! Fix the upstream dependency conflict, or retry with --legacy-peer-deps.
Error: Process completed with exit code 1.
"""

_NPM_V7_RESOLVE = """\
Run actions/checkout@v4
$ npm install
npm error code ERESOLVE
npm error ERESOLVE could not resolve
npm error Could not resolve dependency:
npm error peer react@"^18.0.0" from acme-ui@1.0.0
npm error Fix the upstream dependency conflict, or retry with --legacy-peer-deps.
Error: Process completed with exit code 1.
"""


@pytest.mark.parametrize("log", (_NPM_V6_RESOLVE, _NPM_V7_RESOLVE), ids=("npm-v6", "npm-v7"))
def test_npm_resolver_failures_are_recognised_in_both_output_formats(log: str) -> None:
    """A resolver conflict is DEP-002 under both npm's v6 and v7+ prefixes."""
    result = _diagnose(log)

    assert result.rule_id == "DEP-002"
    assert result.failure_type is FailureType.DEPENDENCY_ERROR


def test_npm_resolver_code_is_not_claimed_by_the_build_rule() -> None:
    """A resolver-level npm code is a dependency diagnosis, never a build one."""
    result = _diagnose(_NPM_V7_RESOLVE)

    assert result.rule_id != "BUILD-001"


_DOCKER_BUILDKIT = """\
#3 [2/6] RUN apt-get update && apt-get install -y build-toolkit
#3 0.934 E: Unable to locate package build-toolkit
#3 ERROR: process "/bin/sh -c apt-get install -y build-toolkit" did not complete successfully: exit code: 100
------
 > [2/6] RUN apt-get update && apt-get install -y build-toolkit:
1.203 ERROR: failed to solve: process "/bin/sh -c apt-get install -y build-toolkit" did not complete successfully: exit code: 100
"""

_DOCKER_BUILDKIT_WITH_PIP = """\
#3 [3/6] RUN pip install --no-cache-dir -r requirements.txt
#3 1.987 ERROR: Could not find a version that satisfies the requirement sqlalchemy==2.0.30
#3 2.041 ERROR: No matching distribution found for sqlalchemy==2.0.30
#3 ERROR: process "/bin/sh -c pip install --no-cache-dir -r requirements.txt" did not complete successfully: exit code: 1
------
 > [3/6] RUN pip install --no-cache-dir -r requirements.txt:
3.412 ERROR: failed to solve: exit code: 1
"""

_MISSING_ENV_VAR = """\
Run actions/checkout@v4
$ ./scripts/publish.sh
publish: error: required environment variable RELEASE_CHANNEL is not set
publish: available channels: nightly, stable
Error: Process completed with exit code 1.
"""

_YAML_PARSE_ERROR = """\
##[group]Validate workflow definition
Invalid workflow file: '.github/workflows/release.yml'
yaml: line 27: mapping values are not allowed in this context
Error: Process completed with exit code 1.
"""


@pytest.mark.parametrize(
    ("log", "rule_id"),
    (
        (_DOCKER_BUILDKIT, "BUILD-001"),
        # pip's own complaints are prefixed by the BuildKit step too; the container
        # build is still the diagnosis, not the resolver inside it.
        (_DOCKER_BUILDKIT_WITH_PIP, "BUILD-001"),
        (_MISSING_ENV_VAR, "BUILD-001"),
        (_YAML_PARSE_ERROR, "BUILD-001"),
    ),
    ids=(
        "buildkit-step",
        "buildkit-pip-inside-step",
        "missing-env-var",
        "yaml-parse-error",
    ),
)
def test_build_and_configuration_signatures(log: str, rule_id: str) -> None:
    """Container, environment, and definition failures are build/config diagnoses."""
    result = _diagnose(log)

    assert result.rule_id == rule_id
    assert result.failure_type is FailureType.BUILD_OR_CONFIG_ERROR


def test_buildkit_failure_names_the_failing_step() -> None:
    """The diagnosis quotes the BuildKit step that failed, not only the solver verdict."""
    result = _diagnose(_DOCKER_BUILDKIT)

    assert any("step 2 of 6" in item.explanation for item in result.evidence)


def test_ingestion_hint_agrees_with_the_diagnosis_on_a_missing_module() -> None:
    """A hint that disagrees with the rules is disclosed, so keep them consistent.

    Both layers classify a module the interpreter cannot find as a dependency problem.
    When they did disagree the result still preferred the log evidence, but every
    diagnosis then carried a caveat explaining its own input -- noise that says nothing
    about the failure being looked at.
    """
    from openmedic.ingestion import classify_log_text

    log = "Traceback (most recent call last):\nModuleNotFoundError: No module named 'requests'\n"
    result = _diagnose(log)

    assert classify_log_text(log) is FailureType.DEPENDENCY_ERROR
    assert result.failure_type is FailureType.DEPENDENCY_ERROR
    assert not any("log evidence was preferred" in item for item in result.limitations)
