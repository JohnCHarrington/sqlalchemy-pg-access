from collections import defaultdict
from dataclasses import dataclass
from typing import FrozenSet

import sqlalchemy as sa

from sqlalchemy_pg_access.registry import register_grant


@dataclass(frozen=True)
class Grant:
    actions: set[str]
    roles: set[str]


def grant_permissions(actions: list[str], to: list[str]):
    def decorator(cls):
        register_grant(cls, Grant(actions, to))
        return cls

    return decorator


def simplify_table_grants(grants: list[Grant]) -> list[Grant]:
    grouped: dict[FrozenSet[str], set[str]] = defaultdict(set)

    for grant in grants:
        action_key = frozenset(action.upper() for action in grant.actions)
        grouped[action_key].update(grant.roles)

    # Construct sorted, normalized Grant objects
    simplified = [
        Grant(actions=set(sorted(action_key)), roles=set(sorted(roles)))
        for action_key, roles in grouped.items()
    ]

    # Sort output for deterministic ordering
    return sorted(simplified, key=lambda g: (tuple(g.actions), tuple(g.roles)))


def get_existing_grants(connection, table_name, schema="public"):
    query = sa.text("""
        SELECT grantee, privilege_type
        FROM information_schema.role_table_grants
        WHERE table_name = :table
        AND table_schema = :schema
    """)
    rows = connection.execute(query, {"table": table_name, "schema": schema})

    grants = [Grant(row["grantee"], row["privilege_type"].upper()) for row in rows]

    return simplify_table_grants(grants)


def grant_identity(grant: Grant) -> tuple[FrozenSet[str], FrozenSet[str]]:
    return frozenset(grant.actions), frozenset(grant.roles)


def diff_simplified_grants(
    existing: list[Grant], desired: list[Grant]
) -> tuple[list[Grant], list[Grant]]:
    existing_set = {grant_identity(g): g for g in existing}
    desired_set = {grant_identity(g): g for g in desired}

    to_grant = [desired_set[key] for key in desired_set.keys() - existing_set.keys()]
    to_revoke = [existing_set[key] for key in existing_set.keys() - desired_set.keys()]

    return to_grant, to_revoke
