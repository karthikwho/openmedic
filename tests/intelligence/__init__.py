"""Tests for the OpenMedic intelligence layer (recurrence, cascades, benchmark).

Every test in this package is offline and deterministic. Files here deliberately define
their own incident and diagnosis helpers so that no test depends on a diagnosis engine,
provider, or network being available.
"""
