"""Minimal check file used by validation tests.

Named ``*_check.py`` so the OpenMedic test run does not collect it, while a validation run
inside a disposable copy of this directory does. It exists only to give the runner a real,
deterministic, offline check to execute.
"""


def test_arithmetic_is_stable():
    """Assert something trivially true so the check always passes."""
    assert 1 + 1 == 2
