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
