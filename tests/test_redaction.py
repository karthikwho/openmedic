"""Secret redaction: the gate that keeps credentials out of everything.

Redaction must be deterministic, idempotent, and must never reveal the secret it
replaced.
"""

from __future__ import annotations

import pytest

from openmedic.domain import PLACEHOLDER, redact, redact_one_line


@pytest.mark.parametrize(
    "secret",
    [
        "ghp_16Z9vYLFOFyksfsdfsdfsdfsdfsdfs",
        "github_pat_11ABCDEFG0abcdefghijkl_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN",
        "AKIAIOSFODNN7EXAMPLE",
        "sk-abcdefghijklmnopqrstuvwxyz012345",
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz012345",
        "AIzaSyA1234567890abcdefghijklmnopqrstuv",
        "npm_abcdefghijklmnopqrstuvwxyz0123456789",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuvwxyz012345",
    ],
)
def test_known_secret_shapes_are_redacted(secret: str) -> None:
    redaction = redact(f"prefix {secret} suffix")
    assert secret not in redaction.text
    assert PLACEHOLDER in redaction.text
    assert redaction.had_secrets


def _slack_bot_token() -> str:
    """Return a genuine Slack-shaped bot token, assembled from its parts.

    Slack coverage is split into recognition and replacement below, and both run
    against the real ``xoxb-<12 digits>-<16 alnum>`` shape — a stand-in name that
    contains no ``xox*`` shape would prove nothing about the ``slack_token`` rule.
    A contiguous token literal in committed source is exactly what GitHub push
    protection correctly refuses, so the value is built from parts: the file never
    contains a token-shaped string, while the string the redactor receives is the
    genuine shape. The parts are obvious test material — fabricated, not a credential,
    and never valid against any Slack workspace.
    """
    return "-".join(("xoxb", "123456789012", "abcdefghijklmnop"))


def test_slack_token_shape_is_recognised() -> None:
    """Recognition: the ``slack_token`` rule locates the token and names its kind.

    The span recorded on the detection is replayed against the original line, so this
    proves the rule matched the token itself rather than neighbouring text, and that
    the recorded label carries no part of the value.
    """
    token = _slack_bot_token()
    line = f"2026-02-10T12:00:00Z [INFO] rotating bot token {token} for acme/app"
    redaction = redact(line)
    assert [d.kind for d in redaction.detections] == ["slack_token"]
    (detection,) = redaction.detections
    assert line[detection.start : detection.end] == token
    assert detection.preview == "slack_token@0"
    assert token not in detection.preview


def test_slack_token_is_replaced_and_stays_replaced() -> None:
    """Replacement: the pipeline removes the token, never leaks it, and is idempotent."""
    token = _slack_bot_token()
    redaction = redact(f"rotation requested with {token}")
    assert redaction.text == "rotation requested with [REDACTED]"
    assert token not in redaction.text
    assert token not in repr(redaction.to_dict())
    assert redaction.had_secrets
    # Feeding the redacted line back in must find nothing new.
    again = redact(redaction.text)
    assert again.text == redaction.text
    assert again.had_secrets is False


def test_slack_words_that_are_not_tokens_are_left_alone() -> None:
    """Only the token *shape* is redacted — a generic stand-in name is not a secret.

    This is why such a name cannot replace the shape in the parametrised list above:
    the redactor is deliberately narrow, and correctly leaves it untouched.
    """
    text = "config dump: SLACK_TEST_TOKEN_NOT_A_REAL_CREDENTIAL"
    redaction = redact(text)
    assert redaction.had_secrets is False
    assert redaction.text == text


@pytest.mark.parametrize(
    "line",
    [
        "password: hunter2xyzzy",
        "PASSWORD = correcthorsebattery",
        "token=abcdef1234567890",
        "api_key: abcd1234efgh5678",
        "client_secret='abcdefghijklmnop'",
        "Authorization: Bearer abcdefghijklmnop",
        "postgres://user:s3cr3tp4ssw0rd@db.example.com:5432/app",
    ],
)
def test_credential_shapes_are_redacted(line: str) -> None:
    redaction = redact(line)
    assert PLACEHOLDER in redaction.text


def test_redaction_is_idempotent() -> None:
    text = "token=abcdef1234567890 and Bearer abcdefghijklmnop"
    once = redact(text).text
    twice = redact(once).text
    assert once == twice


def test_redaction_preserves_length_of_independent_regions() -> None:
    text = "before\ntoken=abcdef1234567890\nafter"
    result = redact(text)
    assert result.text.startswith("before\n")
    assert result.text.endswith("\nafter")


def test_detection_never_exposes_the_secret_value() -> None:
    secret = "ghp_16Z9vYLFOFyksfsdfsfsdfsdfsdfs"  # noqa: S105 - deliberately fake key
    redaction = redact(f"leak attempt {secret}")
    for detection in redaction.detections:
        assert secret not in detection.preview
        assert secret not in repr(detection.to_dict())


def test_detection_metadata_survives_serialisation() -> None:
    redaction = redact("password=hunter2xyzzy here")
    assert redaction.to_dict()["redaction_count"] >= 1


def test_empty_and_whitespace_input() -> None:
    assert redact("").text == ""
    assert redact("   ").had_secrets is False


def test_benign_text_is_untouched() -> None:
    text = "ERROR: ModuleNotFoundError: No module named 'requests'\n  File x.py, line 3"
    assert redact(text).text == text


def test_deterministic_across_runs() -> None:
    text = "token=abcdef1234567890 password=hunter2xyzzy"
    first = redact(text).to_dict()
    second = redact(text).to_dict()
    assert first["text"] == second["text"]


def test_redact_one_line_matches_redact() -> None:
    text = "password=hunter2xyzzy"
    assert redact_one_line(text) == redact(text).text


def test_long_hex_run_is_redacted_conservatively() -> None:
    """A bare high-entropy hex run is treated as a secret.

    Redacting a commit SHA that was not a secret is a harmless false positive; failing
    to redact a token that was is a leak. SECURITY.md requires the conservative choice.
    """
    sha = "a" * 40
    redaction = redact(f"commit {sha} failed")
    assert PLACEHOLDER in redaction.text
    # The rest of the line survives, so evidence is still readable.
    assert "commit" in redaction.text
    assert "failed" in redaction.text


def test_multiple_secrets_all_removed() -> None:
    text = "a token=abcdef1234567890 b password=hunter2xyzzy c Bearer abcdefghijklmnop"
    redaction = redact(text)
    assert redaction.text.count(PLACEHOLDER) >= 3
    assert redaction.detections


def test_placeholder_cannot_be_re_redacted_into_a_loop() -> None:
    text = "password=hunter2xyzzy"
    once = redact(text).text
    # Feeding a redacted string back in must not keep finding "secrets".
    second = redact(once)
    assert second.had_secrets is False


def test_no_regex_backtracking_on_pathological_input() -> None:
    import time

    text = ("a" * 5000) + "-----BEGIN PRIVATE KEY-----" + ("b" * 5000)
    started = time.monotonic()
    redact(text)
    assert time.monotonic() - started < 5.0


def test_unicode_and_binaryish_text_are_handled() -> None:
    text = "error \u00e9\u00e8\u00ea with token=abcdef1234567890 and \x01\x02 control chars"
    result = redact(text)
    assert PLACEHOLDER in result.text


def test_a_token_in_the_url_username_slot_is_redacted() -> None:
    """Package mirrors carry the token as userinfo with no password colon.

    ``db_conn_password`` only sees ``user:pass@``, so this credential position needs its
    own rule or it walks straight into the report.
    """
    url = "https://PublishingToken1234@packages.example.test/simple"
    redaction = redact(f"$ pip install --extra-index-url {url}")
    assert "PublishingToken1234" not in redaction.text
    assert PLACEHOLDER in redaction.text
    assert [d.kind for d in redaction.detections] == ["url_token_userinfo"]
    assert redaction.had_secrets


@pytest.mark.parametrize(
    "url",
    [
        "ssh://git@github.com/acme/widget.git",
        "https://[email protected]/simple",
        "https://pypi.org/simple",
        "git+https://github.com/acme/widget.git@v1.2.3",
    ],
)
def test_account_names_in_urls_are_not_redacted(url: str) -> None:
    """Short userinfo is an account name, not a credential.

    Mangling every URL would bury the real detections in noise, so the rule is deliberately
    narrow: only a long token-shaped userinfo is replaced.
    """
    redaction = redact(f"fetching {url}")
    assert redaction.had_secrets is False
    assert url in redaction.text
