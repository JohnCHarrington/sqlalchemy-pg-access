from collections import defaultdict
from dataclasses import dataclass
from typing import FrozenSet

import sqlalchemy as sa

from sqlalchemy_pg_access.registry import register_grant


@dataclass(frozen=True)
class Grant:
    action: str
    role: str


def grant_permissions(actions: list[str], to: list[str]):
    def decorator(cls):
        for action in actions:
            for role in to:
                register_grant(cls, Grant(action, role))
        return cls

    return decorator


def get_existing_grants(connection, table_name, schema="public"):
    superusers = [
        row[0]
        for row in connection.execute(
            sa.text("SELECT rolname FROM pg_roles WHERE rolsuper")
        ).fetchall()
    ]

    query = sa.text("""
        SELECT grantee, privilege_type
        FROM information_schema.role_table_grants
        WHERE table_name = :table
        AND table_schema = :schema
    """)
    rows = connection.execute(query, {"table": table_name, "schema": schema})

    grants = [Grant(row[1].upper(), row[0]) for row in rows if row[0] not in superusers]

    return grants


def grant_identity(grant: Grant) -> tuple[str, str]:
    return grant.action, grant.role


def diff_simplified_grants(
    existing: list[Grant], desired: list[Grant]
) -> tuple[list[Grant], list[Grant]]:
    existing_set = {grant_identity(g): g for g in existing}
    desired_set = {grant_identity(g): g for g in desired}

    to_grant = [desired_set[key] for key in desired_set.keys() - existing_set.keys()]
    to_revoke = [existing_set[key] for key in existing_set.keys() - desired_set.keys()]

    return to_grant, to_revoke


def find_sequence_names(table: sa.Table) -> list[str]:
    sequence_names = []

    for column in table.columns:
        if isinstance(column.default, sa.Sequence):
            seq_name = column.default.name
            if table.schema:
                seq_name = f"{table.schema}.{seq_name}"
            sequence_names.append(seq_name)

        elif column.autoincrement and column.server_default is not None:
            seq_name = f"{table.name}_{column.name}_seq"
            if table.schema:
                seq_name = f"{table.schema}.{seq_name}"
            sequence_names.append(seq_name)

    return sequence_names
