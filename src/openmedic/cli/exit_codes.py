"""Documented process exit codes.

``docs/TRD.md`` section 5 requires that invalid input, failed validation, an unavailable
integration, and an unresolved repair each exit non-zero, and that the meanings are
documented. This module is the single place those numbers are defined; the CLI maps a
domain error to one of them via :meth:`openmedic.domain.errors.OpenMedicError.exit_code`.

Exit code 2 is reserved by Click/Typer for usage errors, so it is not reused here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

OK: Final = 0
UNEXPECTED_ERROR: Final = 1
USAGE_ERROR: Final = 2
INVALID_INPUT: Final = 3
VALIDATION_FAILED: Final = 4
INTEGRATION_UNAVAILABLE: Final = 5
UNRESOLVED_REPAIR: Final = 6
HUMAN_REVIEW_REQUIRED: Final = 7

#: Exit code -> documented meaning. Rendered by ``openmedic --help``.
EXIT_CODES: Final[tuple[tuple[int, str], ...]] = (
    (OK, "success"),
    (UNEXPECTED_ERROR, "unexpected internal error"),
    (USAGE_ERROR, "invalid command-line usage"),
    (INVALID_INPUT, "input data was malformed or failed validation"),
    (VALIDATION_FAILED, "a required validation check did not pass"),
    (INTEGRATION_UNAVAILABLE, "an external integration was unreachable or unauthorised"),
    (UNRESOLVED_REPAIR, "the requested repair could not be completed or was not approved"),
    (HUMAN_REVIEW_REQUIRED, "the action requires explicit human review before proceeding"),
)


@dataclass(frozen=True, slots=True)
class ExitCodeDoc:
    """One row of the exit-code table shown in ``--help``."""

    code: int
    meaning: str

    def render(self) -> str:
        """Render the code and its meaning as ``<code>  <meaning>``."""
        return f"{self.code}  {self.meaning}"


def exit_code_help() -> str:
    """Return the multi-line exit-code documentation block."""
    return "\n".join(ExitCodeDoc(code=c, meaning=m).render() for c, m in EXIT_CODES)
