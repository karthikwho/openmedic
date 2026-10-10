"""Forensics: normalisation removes volatile noise without destroying evidence."""

from __future__ import annotations

from openmedic.forensics import fingerprint, line_index, normalize_log


def test_timestamps_and_temp_paths_normalise_away() -> None:
    raw = (
        "2026-10-09T12:00:01Z Building in /tmp/build-abc123/x\n"
        "2026-10-09T12:00:02Z Port 8080 listening\n"
    )
    result = normalize_log(raw)
    assert "<TIMESTAMP>" in result.normalized
    assert "<TMPPATH>" in result.normalized
    assert "12:00:01" not in result.normalized


def test_raw_evidence_is_never_destroyed() -> None:
    raw = "ERROR: ModuleNotFoundError: No module named 'requests'\nat 12:00:01"
    result = normalize_log(raw)
    assert result.raw == raw
    assert "ModuleNotFoundError" in result.normalized


def test_identical_failure_fingerprints_identically_across_volatile_values() -> None:
    base = (
        "2026-10-09T{h}:00:01Z step started in /tmp/job-{run}\n"
        "ERROR: ModuleNotFoundError: No module named 'requests'\n"
        "port {p} closed\n"
    )
    first = normalize_log(base.format(h="11", run="aaa", p="8080"))
    second = normalize_log(base.format(h="19", run="zzz", p="9091"))
    assert fingerprint(first.normalized) == fingerprint(second.normalized)


def test_different_failures_fingerprint_differently() -> None:
    one = normalize_log("ERROR: ModuleNotFoundError: No module named 'requests'\n")
    two = normalize_log("SyntaxError: invalid syntax\n")
    assert fingerprint(one.normalized) != fingerprint(two.normalized)


def test_line_index_covers_every_line() -> None:
    raw = "line one\nline two\nline three"
    result = normalize_log(raw)
    index = line_index(result)
    assert set(index.values()) == {1, 2, 3}
    assert index[2] == 2


def test_secrets_are_redacted_in_parallel_with_normalisation() -> None:
    raw = "password=hunter2xyzzy\nERROR: boom\n"
    result = normalize_log(raw)
    assert "hunter2" not in result.redacted_raw
    assert "hunter2" not in result.normalized
    assert "hunter2" in result.raw  # raw evidence is preserved in memory


def test_redaction_can_be_disabled_for_internal_use() -> None:
    raw = "password=hunter2xyzzy\nERROR: boom\n"
    result = normalize_log(raw, redact_secrets=False)
    assert result.redacted_raw == raw


def test_empty_log_does_not_crash() -> None:
    result = normalize_log("")
    assert result.normalized == ""
    assert result.line_count == 0


def test_substitution_counts_are_reported() -> None:
    result = normalize_log("2026-10-09T12:00:01Z and 12:00:02 again")
    assert result.substitutions_applied.get("iso8601") == 1


def test_fingerprint_is_stable() -> None:
    text = normalize_log("ERROR: boom\n").normalized
    assert fingerprint(text) == fingerprint(text)


def test_fingerprint_ignores_blank_lines_and_trailing_whitespace() -> None:
    one = fingerprint(normalize_log("ERROR: boom\n").normalized)
    two = fingerprint(normalize_log("ERROR: boom   \n\n").normalized)
    assert one == two


def test_normalisation_is_deterministic() -> None:
    raw = "2026-10-09T12:00:01Z /tmp/x error\n"
    assert normalize_log(raw).normalized == normalize_log(raw).normalized
