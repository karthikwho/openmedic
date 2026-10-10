"""Persistence layer: connection management, migrations, and the incident repository.

Nothing here reaches into another OpenMedic layer except the domain package. The CLI and
the later API both drive :class:`IncidentRepository`; business logic lives above this
package, not inside it.
"""

from __future__ import annotations

from .database import connect, db_info, init_db
from .migrations import (
    LATEST_VERSION,
    MIGRATIONS,
    latest_version,
    migrate,
    migrate_atomic,
    migration_versions,
    pending_migrations,
    transaction,
    user_version,
)
from .repository import IncidentRepository

__all__ = [
    "LATEST_VERSION",
    "MIGRATIONS",
    "IncidentRepository",
    "connect",
    "db_info",
    "init_db",
    "latest_version",
    "migrate",
    "migrate_atomic",
    "migration_versions",
    "pending_migrations",
    "transaction",
    "user_version",
]
