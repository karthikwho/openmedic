"""Safety suite: the invariants in ``docs/SECURITY.md`` as executable tests.

These tests deliberately depend only on the domain and forensics layers, so they keep
passing even while higher layers are being rebuilt. CI runs this directory as its own
job (``safety-gate``) so a regression is unmistakable.
"""

from __future__ import annotations
