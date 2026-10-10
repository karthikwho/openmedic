"""SQLite connection management for the local incident store.

Every connection is opened in autocommit mode with WAL journalling and foreign keys
enabled, and transaction boundaries are therefore always explicit (see
:func:`openmedic.persistence.migrations.transaction`). That is a deliberate choice: the
repository must never rely on an implicit transaction that could commit halfway through
an incident update.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, Final

from ..domain.errors import PersistenceError
from .migrations import latest_version, migration_versions, user_version

#: SQLite database name that means "in memory". Useful in tests; never used by the CLI.
_MEMORY: Final = ":memory:"

#: How long a connection waits for a competing writer before giving up.
_BUSY_TIMEOUT_MS: Final = 5_000

#: Journal modes that are acceptable after configuration. ``memory`` is what an in-memory
#: database always reports and cannot be changed.
_ACCEPTABLE_JOURNAL_MODES: Final = frozenset({"wal", "memory"})


def connect(db_path: Path | str, *, create: bool = True) -> sqlite3.Connection:
    """Open the incident store at ``db_path`` and configure it for durable local use.

    With ``create=False`` a missing file is an error instead of an empty database, which
    is what read-only callers (``openmedic incidents show``) want to see. Missing parent
    directories are created when ``create`` is true.
    """
    if isinstance(db_path, str) and db_path.strip() == _MEMORY:
        return _configure(sqlite3.connect(_MEMORY, isolation_level=None))

    path = Path(db_path).expanduser()
    if not path.exists():
        if not create:
            msg = f"incident store does not exist: {path}"
            raise PersistenceError(msg)
        parent = path.parent
        if not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
    try:
        conn = sqlite3.connect(path, isolation_level=None, timeout=_BUSY_TIMEOUT_MS / 1000)
    except sqlite3.Error as exc:
        msg = f"cannot open incident store {path}: {type(exc).__name__}"
        raise PersistenceError(msg) from exc
    return _configure(conn)


def init_db(db_path: Path | str) -> sqlite3.Connection:
    """Open ``db_path``, migrate it to the latest schema, and return the connection."""
    from .migrations import migrate  # local import: migrations imports this module

    conn = connect(db_path)
    try:
        migrate(conn)
    except BaseException:
        conn.close()
        raise
    return conn


def db_info(db_path: Path | str) -> dict[str, object]:
    """Return a diagnostics snapshot of the incident store.

    The result reports the schema version, how many migrations are still pending, the
    incident counts (total and per lifecycle state), and the file size. It never writes:
    a missing database is reported as such rather than created.
    """
    path = Path(db_path).expanduser() if not _is_memory(db_path) else None
    info: dict[str, object] = {
        "path": str(db_path),
        "exists": path is None or path.exists(),
        "schema_version": 0,
        "latest_schema_version": latest_version(),
        "pending_migrations": list(migration_versions()),
        "incidents": 0,
        "by_state": {},
        "file_size_bytes": 0,
    }
    if path is not None:
        info["file_size_bytes"] = path.stat().st_size if path.exists() else 0
    if not info["exists"]:
        return info

    conn = connect(db_path, create=False)
    try:
        version = user_version(conn)
        info["schema_version"] = version
        info["pending_migrations"] = [v for v in migration_versions() if v > version]
        info["journal_mode"] = _pragma(conn, "PRAGMA journal_mode")
        if _table_exists(conn, "incidents"):
            info["incidents"] = int(conn.execute("SELECT count(*) FROM incidents").fetchone()[0])
            info["by_state"] = {
                str(state): int(count)
                for state, count in conn.execute(
                    "SELECT state, count(*) FROM incidents GROUP BY state ORDER BY state"
                )
            }
    finally:
        conn.close()
    return info


def _is_memory(db_path: Path | str) -> bool:
    """Return whether ``db_path`` names an in-memory database."""
    return isinstance(db_path, str) and db_path.strip() == _MEMORY


def _configure(conn: sqlite3.Connection) -> sqlite3.Connection:
    """Apply the pragmas every OpenMedic connection relies on, and verify them."""
    journal_mode = _pragma(conn, "PRAGMA journal_mode=WAL")
    if journal_mode not in _ACCEPTABLE_JOURNAL_MODES:
        conn.close()
        msg = (
            f"cannot enable WAL journalling (SQLite reported '{journal_mode}'); refusing "
            "to run against a store that does not journal durably"
        )
        raise PersistenceError(msg)
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    if int(_pragma(conn, "PRAGMA foreign_keys") or 0) != 1:
        conn.close()
        msg = "cannot enable foreign key enforcement on the incident store"
        raise PersistenceError(msg)
    return conn


def _pragma(conn: sqlite3.Connection, statement: str) -> Any:
    """Execute a pragma and return its first column, stepping the statement."""
    row = conn.execute(statement).fetchone()
    return row[0] if row else None


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    """Return whether a table called ``name`` exists."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None
