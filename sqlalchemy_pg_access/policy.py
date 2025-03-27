import json
import re
from typing import Callable

from sqlalchemy import Table, event, text
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.schema import SchemaItem
from sqlalchemy.sql.compiler import DDLCompiler
from sqlalchemy.sql.elements import ClauseElement

from sqlalchemy_pg_access.registry import get_policies_for_model, register_rls_policy


# Our fundamental class to hold an RLS policy definition.
class RLSPolicy(SchemaItem):
    def __init__(
        self,
        table: Table,
        name: str,
        commands: list[str] | None = None,
        roles: list[str] | None = None,
    ):
        self.table = table
        self.name = name
        self.commands = commands  # e.g., SELECT, INSERT, etc.
        self.roles = roles  # list of roles to which the policy applies
        self.using_clause: ClauseElement | None = None
        self.with_check_clause: ClauseElement | None = None

        super().__init__()

    def to_sql(self, table_name: str, dialect) -> str:
        def compile_clause(clause):
            if clause is None:
                return None
            compiled = clause.compile(
                dialect=dialect, compile_kwargs={"literal_binds": True}
            )
            return str(compiled)

        using_sql = compile_clause(self.using_clause)
        with_check_sql = compile_clause(self.with_check_clause)

        sql_parts = [
            f"CREATE POLICY {self.name} ON {table_name}",
        ]
        if self.commands:
            sql_parts.append(f"FOR {', '.join(self.commands)}")
        if self.roles:
            sql_parts.append(f"TO {', '.join(self.roles)}")
        if using_sql:
            sql_parts.append(f"USING ({using_sql})")
        if with_check_sql:
            sql_parts.append(f"WITH CHECK ({with_check_sql})")
        return " ".join(sql_parts) + ";"

    def compile(self, dialect=None, compile_kwargs=None):
        if dialect is None:
            dialect = postgresql.dialect()
        if compile_kwargs is None:
            compile_kwargs = {"literal_binds": True}
        compiler = DDLCompiler(dialect, None)
        return compiler.process(self, **compile_kwargs)


def rls_policy(
    name: str,
    commands: list[str] | None = None,
    roles: list[str] | None = None,
    using: ClauseElement | Callable = None,
    with_check: ClauseElement | Callable = None,
) -> Callable:
    def decorator(cls):
        policy = RLSPolicy(
            name=name, commands=commands, roles=roles, table=cls.__table__
        )

        if callable(using):
            policy.using_clause = using(cls)
        elif using is not None:
            policy.using_clause = using

        if callable(with_check):
            policy.with_check_clause = with_check(cls)
        elif with_check is not None:
            policy.with_check_clause = with_check

        register_rls_policy(cls, policy)
        return cls

    return decorator


@compiles(RLSPolicy)
def compile_create_rls_policies(policy, compiler, **kw) -> str:
    table_name = compiler.preparer.format_table(policy.table)
    # Assume each policy has a to_sql method.
    sql_statement = policy.to_sql(table_name, compiler.dialect)
    return sql_statement


@event.listens_for(Table, "after_create")
def execute_rls_policies(target, connection, **kw):
    policies = get_policies_for_model(target)
    for policy in policies:
        if not policy.table_name:
            policy.table_name = target.name
        stmt = policy.compile(
            dialect=connection.dialect, compile_kwargs={"literal_binds": True}
        )
        connection.execute(text(stmt))


def get_existing_policies_as_objects(connection, table, dialect) -> list:
    schema = table.schema or "public"

    rows = connection.execute(
        text("""
        SELECT
            pol.polname AS name,
            pol.polcmd AS command,
            pol.polroles AS role_oids,
            pg_get_expr(pol.polqual, pol.polrelid) AS using_clause,
            pg_get_expr(pol.polwithcheck, pol.polrelid) AS with_check_clause
        FROM pg_policy pol
        JOIN pg_class cls ON pol.polrelid = cls.oid
        JOIN pg_namespace ns ON cls.relnamespace = ns.oid
        WHERE cls.relname = :table AND ns.nspname = :schema
    """),
        {"table": table.name, "schema": schema},
    ).fetchall()

    # Resolve roles
    role_map = {
        row[0]: row[1]
        for row in connection.execute(
            text("SELECT oid, rolname FROM pg_roles")
        ).fetchall()
    }

    policies = []

    for row in rows:
        roles = [role_map.get(oid) for oid in row[2] if oid in role_map]
        policy = RLSPolicy(
            name=row[0],
            table=table,
            commands=None
            if row[1] == "*"
            else [x.strip().upper() for x in row[1].split(",")],
            roles=roles or None,
        )
        policy.using_clause = text(row[3]) if row[3] else None
        policy.with_check_clause = text(row[4]) if row[4] else None
        policies.append(policy)

    return policies


def diff_rls_policies(
    existing: list[RLSPolicy], desired: list[RLSPolicy]
) -> tuple[list[str], list[str], list[str]]:
    """
    Returns (to_create, to_replace, to_drop) — all are lists of policy names
    """
    to_create = []
    to_replace = []
    to_drop = []

    existing_names = [x.name for x in existing]
    desired_names = [x.name for x in desired]

    for policy in desired:
        if policy.name not in existing_names:
            to_create.append(policy.name)
        else:
            existing_policy = next(x for x in existing if x.name == policy.name)
            if (
                existing_policy.commands != policy.commands
                or existing_policy.roles != policy.roles
            ):
                to_replace.append(policy.name)

    for policy in existing:
        if policy.name not in desired_names:
            to_drop.append(policy.name)

    return to_create, to_replace, to_drop
