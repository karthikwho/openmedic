"""Versioned, forward-only SQLite schema migrations.

The incident store is a single SQLite file, so migrations are hand-rolled and numbered
rather than delegated to a migration framework (TRD section 2, decision 6 in
``docs/IMPLEMENTATION_STATUS.md`` section 5). Three rules are enforced here, because
breaking either of them silently destroys local incident history:

1. **Forward only.** The chain is contiguous and ascending. A database whose recorded
   history is ahead of this build is refused, never "migrated" backwards, and there are
   no destructive back-migrations.
2. **Atomic.** Every migration runs inside one transaction that also carries the version
   marker and the audit row, so an interrupted migration cannot leave a half-applied
   schema behind.
3. **No guessing.** ``PRAGMA user_version`` and the ``schema_migrations`` record table
   must agree. When they do not, the marker was edited by hand and the database is
   rejected instead of being reinterpreted.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Final

from ..domain.contracts import utc_now
from ..domain.errors import PersistenceError

#: Name of the table that records which migrations have been applied. It is part of the
#: contract of this module rather than an implementation detail: it is what makes a
#: hand-edited version marker detectable.
RECORD_TABLE: Final = "schema_migrations"

_MIGRATION_1_SQL: Final = """
CREATE TABLE incidents (
    incident_id     TEXT NOT NULL PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    state           TEXT NOT NULL,
    schema_version  TEXT NOT NULL,
    payload         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    event_timestamp TEXT NOT NULL
);

CREATE UNIQUE INDEX ux_incidents_idempotency_key ON incidents (idempotency_key);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER NOT NULL PRIMARY KEY,
    applied_at TEXT    NOT NULL
);
"""

_MIGRATION_2_SQL: Final = """
CREATE INDEX ix_incidents_state_updated_at ON incidents (state, updated_at);
"""

#: Ensures the audit table exists. The real chain creates it in migration 1; running
#: this first means a migration script can never fail because it forgot to.
_ENSURE_RECORD_TABLE: Final = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER NOT NULL PRIMARY KEY,
    applied_at TEXT    NOT NULL
)
"""

#: Ordered ``(version, SQL)`` pairs. Append only: never renumber, never insert in the
#: middle, never remove an entry once it has shipped.
MIGRATIONS: Final[tuple[tuple[int, str], ...]] = (
    (1, _MIGRATION_1_SQL),
    (2, _MIGRATION_2_SQL),
)

#: Version a freshly created database ends up at. Internal logic derives this from
#: :data:`MIGRATIONS` at call time so the chain stays the single source of truth.
LATEST_VERSION: Final = MIGRATIONS[-1][0]

_SELECT_RECORDED: Final = "SELECT version FROM schema_migrations"

_INSERT_RECORD: Final = "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)"


def migration_versions() -> tuple[int, ...]:
    """Return the known migration versions in ascending order."""
    return tuple(version for version, _ in _chain())


def latest_version() -> int:
    """Return the newest migration version this build knows how to apply."""
    return _chain()[-1][0]


def user_version(conn: sqlite3.Connection) -> int:
    """Return the schema version marker stored in the database header."""
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0]) if row is not None else 0


def pending_migrations(conn: sqlite3.Connection) -> list[int]:
    """Return the migration versions that still have to be applied, in order."""
    current = _verified_version(conn)
    return [version for version, _ in _chain() if version > current]


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block inside one SQLite transaction, rolling back on any error.

    ``connect`` opens connections in autocommit mode so that transaction boundaries are
    always explicit. ``with conn:`` alone is not enough there: it only commits or rolls
    back at exit, so a plain ``with conn:`` would auto-commit each statement on its own.
    """
    if conn.in_transaction:
        msg = (
            "cannot begin a transaction: this connection already has one open. Commit or "
            "roll back the outer transaction before starting another."
        )
        raise PersistenceError(msg)
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    else:
        if conn.in_transaction:
            conn.execute("COMMIT")


def migrate(conn: sqlite3.Connection, *, target: int | None = None) -> int:
    """Apply every pending migration and return the resulting schema version.

    Each migration is applied in its own transaction, so at most one migration is ever
    in flight. Re-running this on an up-to-date database is a no-op. ``target`` may be
    used to migrate only up to a specific version; a target below the current version is
    rejected because there are no back-migrations.
    """
    desired = _resolve_target(conn, target)
    while True:
        current = _verified_version(conn)
        version = next((v for v, _ in _chain() if current < v <= desired), None)
        if version is None:
            return current
        with transaction(conn):
            _apply_migration(conn, version)


def migrate_atomic(db_path: Path | str) -> int:
    """Open ``db_path``, apply every pending migration in one transaction, and close.

    This is the strongest guarantee available: either the whole chain lands or nothing
    changes. It is what ``init_db`` and a fresh CLI invocation need.
    """
    from .database import connect  # local import: database imports this module

    conn = connect(db_path)
    try:
        desired = _resolve_target(conn, None)
        current = _verified_version(conn)
        pending = [version for version, _ in _chain() if current < version <= desired]
        if not pending:
            return current
        with transaction(conn):
            for version in pending:
                _apply_migration(conn, version)
        return _verified_version(conn)
    finally:
        conn.close()


def _chain() -> tuple[tuple[int, str], ...]:
    """Return the validated migration chain.

    Read from the module global on every call so the chain stays a single source of
    truth. Contiguity is checked because a gap would silently skip a schema change.
    """
    migrations = MIGRATIONS
    versions = [version for version, _ in migrations]
    if versions != list(range(1, len(versions) + 1)):
        msg = f"migration versions must be contiguous integers starting at 1, got {versions}"
        raise PersistenceError(msg)
    return migrations


def _resolve_target(conn: sqlite3.Connection, target: int | None) -> int:
    """Validate an explicit migration target and return the version to migrate to."""
    if target is None:
        return latest_version()
    versions = migration_versions()
    if target not in versions:
        msg = f"unknown migration target {target}; known versions are {list(versions)}"
        raise PersistenceError(msg)
    current = _verified_version(conn)
    if target < current:
        msg = (
            f"refusing to downgrade the incident store from schema version {current} to "
            f"{target}: migrations are forward-only and there are no back-migrations"
        )
        raise PersistenceError(msg)
    return target


def _verified_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version, rejecting a database that cannot be trusted.

    A database is trusted when the header marker and the recorded migration history
    agree, and when neither is newer than this build.
    """
    current = user_version(conn)
    recorded = _recorded_versions(conn)
    if not recorded:
        if current != 0:
            msg = (
                f"database reports schema version {current} but {RECORD_TABLE} records "
                "no migrations; refusing to guess the schema of an unversioned database"
            )
            raise PersistenceError(msg)
        return 0
    newest = max(recorded)
    if max(current, newest) > latest_version():
        msg = (
            f"database schema version {max(current, newest)} is newer than this build "
            f"understands ({latest_version()}); upgrade OpenMedic instead of "
            "downgrading the data"
        )
        raise PersistenceError(msg)
    if current != newest:
        msg = (
            f"database schema marker is {current} but {RECORD_TABLE} records {newest}; "
            "the version marker was edited by hand, so the schema cannot be trusted"
        )
        raise PersistenceError(msg)
    if current not in migration_versions():
        msg = (
            f"database schema version {current} is not a known migration version; known "
            f"versions are {list(migration_versions())}"
        )
        raise PersistenceError(msg)
    return current


def _recorded_versions(conn: sqlite3.Connection) -> set[int]:
    """Return the versions recorded in the migration table, or an empty set."""
    if not _table_exists(conn, RECORD_TABLE):
        return set()
    return {int(row[0]) for row in conn.execute(_SELECT_RECORDED)}


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    """Return whether a table called ``name`` exists."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None


def _apply_migration(conn: sqlite3.Connection, version: int) -> None:
    """Execute one migration's statements inside the caller's transaction.

    The version marker and the audit row are written in the same transaction as the
    schema change, so a rollback removes all three.
    """
    try:
        conn.execute(_ENSURE_RECORD_TABLE)
        for statement in _split_statements(dict(_chain())[version]):
            conn.execute(statement)
        conn.execute(f"PRAGMA user_version = {version}")
        conn.execute(
            _INSERT_RECORD,
            (version, _stamp()),
        )
    except sqlite3.Error as exc:
        msg = f"migration {version} failed: {type(exc).__name__}: {exc}"
        raise PersistenceError(msg) from exc


def _stamp() -> str:
    """Return the current UTC time as a canonical ISO-8601 string."""
    return utc_now().isoformat()


def _split_statements(sql: str) -> list[str]:
    """Split a migration script into individual statements.

    ``sqlite3`` cannot execute a multi-statement string inside a transaction, and
    ``executescript`` would commit the surrounding one, so the script is split here. The
    splitter is quote- and comment-aware: a semicolon inside a string literal or after a
    ``--`` comment does not end a statement.
    """
    statements: list[str] = []
    buffer: list[str] = []
    quote: str | None = None
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if quote is not None:
            buffer.append(char)
            if char == quote:
                if index + 1 < length and sql[index + 1] == quote:
                    buffer.append(quote)
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            buffer.append(char)
            index += 1
            continue
        if char == "-" and sql.startswith("--", index):
            end = sql.find("\n", index)
            end = length if end == -1 else end
            buffer.append(sql[index:end])
            index = end
            continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement and _has_sql(statement):
                statements.append(statement)
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    tail = "".join(buffer).strip()
    if tail and _has_sql(tail):
        statements.append(tail)
    return statements


def _has_sql(statement: str) -> bool:
    """Return whether ``statement`` contains anything other than comments and blanks."""
    return any(
        line.strip() and not line.lstrip().startswith("--") for line in statement.splitlines()
    )
