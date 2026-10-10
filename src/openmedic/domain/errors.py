"""Domain errors.

Every error raised by OpenMedic is a subclass of :class:`OpenMedicError` so the CLI can
map a whole family to a single documented exit code while still printing an actionable,
structured message. Messages must never contain secret material.
"""

from __future__ import annotations


class OpenMedicError(Exception):
    """Base class for all expected OpenMedic failures."""

    #: Exit code used by the CLI when this error reaches the top level.
    exit_code = 1

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serialisable representation without secret material."""
        payload = {"error": type(self).__name__, "message": self.message}
        if self.detail:
            payload["detail"] = self.detail
        return payload


class UsageError(OpenMedicError):
    """The invocation itself was wrong (bad flags, missing arguments)."""

    exit_code = 2


class InvalidInputError(OpenMedicError):
    """Input data was present but malformed, unsupported, or failed validation."""

    exit_code = 3


class ValidationFailedError(OpenMedicError):
    """A required validation check did not pass for the candidate being reported."""

    exit_code = 4


class IntegrationUnavailableError(OpenMedicError):
    """An external integration could not be reached or authorised."""

    exit_code = 5


class UnresolvedRepairError(OpenMedicError):
    """The requested repair could not be completed or was not approved."""

    exit_code = 6


class HumanReviewRequiredError(OpenMedicError):
    """The action is allowed only after explicit human review."""

    exit_code = 7


class ContractError(OpenMedicError):
    """A domain contract violates its own invariants.

    Raised by ``pydantic`` validators and by lifecycle checks. It is a programming
    error, not a user error; the CLI reports it as exit code 1 with detail.
    """

    exit_code = 1


class PolicyViolationError(OpenMedicError):
    """A proposed action was rejected by the safety policy."""

    exit_code = 6


class PersistenceError(OpenMedicError):
    """A local storage operation failed."""

    exit_code = 1
