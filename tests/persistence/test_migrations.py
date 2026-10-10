"""Migration tests: versioning, idempotency, atomicity, and refusal to downgrade."""

from __future__ import annotations

import sqlite3

import pytest

from openmedic.domain.errors import PersistenceError
from openmedic.persistence import migrations
from openmedic.persistence.database import connect
from openmedic.persistence.migrations import (
    LATEST_VERSION,
    MIGRATIONS,
    RECORD_TABLE,
    latest_version,
    migrate,
    migrate_atomic,
    migration_versions,
    pending_migrations,
    user_version,
)


def test_fresh_database_migrates_to_latest(conn: sqlite3.Connection) -> None:
    assert user_version(conn) == 0
    assert pending_migrations(conn) == [1, 2]

    assert migrate(conn) == LATEST_VERSION

    assert user_version(conn) == LATEST_VERSION
    assert pending_migrations(conn) == []
    assert latest_version() == LATEST_VERSION


def test_re_running_migrate_is_a_no_op(conn: sqlite3.Connection) -> None:
    assert migrate(conn) == LATEST_VERSION
    recorded = _recorded_versions(conn)

    assert migrate(conn) == LATEST_VERSION
    assert migrate(conn) == LATEST_VERSION

    assert _recorded_versions(conn) == recorded
    assert user_version(conn) == LATEST_VERSION


def test_migrations_are_numbered_contiguously() -> None:
    versions = [version for version, _ in MIGRATIONS]
    assert versions == list(range(1, len(versions) + 1))
    assert migration_versions() == tuple(versions)
    assert versions[-1] == LATEST_VERSION


def test_tables_and_indexes_exist_after_migration(conn: sqlite3.Connection) -> None:
    migrate(conn)
    objects = {
        name
        for (name,) in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','index')"
        )
    }
    assert {"incidents", "schema_migrations"} <= objects
    assert "ux_incidents_idempotency_key" in objects
    assert "ix_incidents_state_updated_at" in objects


def test_hand_lowered_user_version_is_rejected(conn: sqlite3.Connection) -> None:
    migrate(conn)
    conn.execute("PRAGMA user_version = 1")

    with pytest.raises(PersistenceError, match="edited by hand"):
        migrate(conn)

    # The refusal itself must not rewrite anything.
    assert user_version(conn) == 1
    assert _recorded_versions(conn) == [1, 2]
    assert conn.execute("SELECT count(*) FROM incidents").fetchone()[0] == 0


def test_user_version_newer_than_this_build_is_rejected(
    db_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert migrate_atomic(db_path) == LATEST_VERSION

    # Simulate a store written by a build that knows one more migration.
    monkeypatch.setattr(migrations, "MIGRATIONS", MIGRATIONS[:1])
    conn = connect(db_path)
    try:
        with pytest.raises(PersistenceError, match="newer than this build"):
            pending_migrations(conn)
    finally:
        conn.close()


def test_user_version_without_a_migration_record_is_rejected(
    conn: sqlite3.Connection,
) -> None:
    conn.execute("PRAGMA user_version = 1")

    with pytest.raises(PersistenceError, match="no migrations"):
        pending_migrations(conn)


def test_downgrade_target_is_refused(conn: sqlite3.Connection) -> None:
    migrate(conn)

    with pytest.raises(PersistenceError, match="refusing to downgrade"):
        migrate(conn, target=1)

    assert user_version(conn) == LATEST_VERSION


def test_unknown_target_is_refused(conn: sqlite3.Connection) -> None:
    with pytest.raises(PersistenceError, match="unknown migration target"):
        migrate(conn, target=99)
    assert user_version(conn) == 0


def test_migrate_atomic_applies_the_whole_chain_and_is_repeatable(
    db_path: object,
) -> None:
    assert migrate_atomic(db_path) == LATEST_VERSION

    conn = connect(db_path)
    try:
        assert user_version(conn) == LATEST_VERSION
        assert pending_migrations(conn) == []
        assert _recorded_versions(conn) == list(range(1, LATEST_VERSION + 1))
    finally:
        conn.close()

    assert migrate_atomic(db_path) == LATEST_VERSION


def test_failing_migration_rolls_back_only_its_own_transaction(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (
            (1, "CREATE TABLE alpha (x INTEGER);"),
            (2, "CREATE TABLE beta (y INTEGER);"),
            (3, "CREATE TABLE gamma (z INTEGER); THIS IS NOT SQL;"),
        ),
    )

    with pytest.raises(PersistenceError, match="migration 3"):
        migrate(conn)

    # Migrations 1 and 2 were individually committed; migration 3 left nothing behind.
    assert user_version(conn) == 2
    assert _table_exists(conn, "alpha")
    assert _table_exists(conn, "beta")
    assert not _table_exists(conn, "gamma")


def test_migrate_atomic_rolls_back_the_whole_chain(
    db_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (
            (1, "CREATE TABLE alpha (x INTEGER);"),
            (2, "CREATE TABLE beta (y INTEGER); THIS IS NOT SQL;"),
        ),
    )

    with pytest.raises(PersistenceError, match="migration 2"):
        migrate_atomic(db_path)

    conn = connect(db_path)
    try:
        assert user_version(conn) == 0
        assert not _table_exists(conn, "alpha")
        assert not _table_exists(conn, "beta")
    finally:
        conn.close()


def test_migrate_atomic_walks_a_longer_chain(
    db_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        (
            (1, "CREATE TABLE alpha (x INTEGER);"),
            (2, "CREATE INDEX ix_alpha ON alpha (x);"),
            (3, "CREATE TABLE beta (y INTEGER);"),
        ),
    )
    assert migrate_atomic(db_path) == 3

    conn = connect(db_path)
    try:
        assert _table_exists(conn, "alpha")
        assert _table_exists(conn, "beta")
        assert user_version(conn) == 3
    finally:
        conn.close()


def test_unversioned_database_that_already_has_tables_is_refused(
    conn: sqlite3.Connection,
) -> None:
    conn.execute("CREATE TABLE incidents (x)")
    conn.commit()

    with pytest.raises(PersistenceError, match="migration 1 failed"):
        migrate(conn)

    # The failed migration took nothing with it.
    assert user_version(conn) == 0
    assert not _table_exists(conn, RECORD_TABLE)


def test_non_contiguous_migration_chain_is_refused(
    conn: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        migrations,
        "MIGRATIONS",
        ((1, "CREATE TABLE alpha (x INTEGER);"), (3, "CREATE TABLE beta (y INTEGER);")),
    )
    with pytest.raises(PersistenceError, match="contiguous"):
        migrate(conn)


def test_transaction_requires_no_open_transaction(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        with (
            pytest.raises(PersistenceError, match="already has one open"),
            migrations.transaction(conn),
        ):
            pass  # pragma: no cover - never reached
    finally:
        conn.execute("ROLLBACK")


def test_split_statements_knows_about_quotes_and_comments() -> None:
    sql = (
        "CREATE TABLE t (x TEXT DEFAULT 'a;b'); "
        "INSERT INTO t VALUES ('it''s; still fine'); -- trailing; comment"
    )
    assert migrations._split_statements(sql) == [
        "CREATE TABLE t (x TEXT DEFAULT 'a;b')",
        "INSERT INTO t VALUES ('it''s; still fine')",
    ]


def test_split_statements_keeps_leading_comments() -> None:
    sql = "-- leading; comment\nCREATE TABLE t (x);"
    assert migrations._split_statements(sql) == ["-- leading; comment\nCREATE TABLE t (x)"]


def test_split_statements_ignores_empty_statements() -> None:
    assert migrations._split_statements("CREATE TABLE t (x);;\n\n") == ["CREATE TABLE t (x)"]


def _recorded_versions(conn: sqlite3.Connection) -> list[int]:
    return [
        int(row[0])
        for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
    ]


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)
    ).fetchone()
    return row is not None
