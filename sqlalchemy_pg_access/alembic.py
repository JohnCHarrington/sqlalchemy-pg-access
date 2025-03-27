import logging
from collections import defaultdict

import sqlalchemy as sa

from sqlalchemy_pg_access.grant import (
    Grant,
    diff_simplified_grants,
    find_sequence_names,
    get_existing_grants,
)
from sqlalchemy_pg_access.policy import (
    diff_rls_policies,
    get_existing_policies_as_objects,
)
from sqlalchemy_pg_access.registry import (
    get_grants_for_table_name,
    get_policies_for_table_name,
)

log = logging.getLogger(__name__)

try:
    from alembic.operations import ops
except ImportError:
    raise ImportError(
        "Alembic support requires alembic! Install sqlmodel_postgres_rls[alembic]"
    )


def process_revision_directives_base(context, revision, directives):
    migration_script = directives[0]
    connection = context.connection
    dialect = connection.dialect

    # target_metadata might be a list or a single MetaData.
    target_metadata = context.config.attributes.get("target_metadata")
    metadatas = (
        target_metadata if isinstance(target_metadata, list) else [target_metadata]
    )

    return migration_script, connection, dialect, metadatas


def generate_process_revision_directives(
    rls=True, schema=False, grant_permissions=True, grant_schema_permissions=True
):
    def process_revision_directives(context, revision, directives):
        migration_script = directives[0]

        if grant_schema_permissions:
            grant_schema_up, grant_schema_down = (
                process_grant_schema_revision_directives(context, revision, directives)
            )
            migration_script.upgrade_ops.ops.extend(grant_schema_up)
            migration_script.downgrade_ops.ops[:0] = grant_schema_down

        if grant_permissions:
            grant_up, grant_down = process_grant_revision_directives(
                context, revision, directives
            )
            migration_script.upgrade_ops.ops.extend(grant_up)
            migration_script.downgrade_ops.ops[:0] = grant_down

        if rls:
            rls_up, rls_down = process_rls_revision_directives(
                context, revision, directives
            )
            migration_script.upgrade_ops.ops.extend(rls_up)
            migration_script.downgrade_ops.ops[:0] = rls_down

        if schema:
            schema_up, schema_down = process_schema_revision_directives(
                context, revision, directives
            )
            migration_script.upgrade_ops.ops[:0] = schema_up
            migration_script.downgrade_ops.ops.extend(schema_down)

    return process_revision_directives


def process_schema_revision_directives(context, revision, directives):
    migration_script, connection, dialect, metadatas = process_revision_directives_base(
        context, revision, directives
    )

    schemas = set()

    for metadata in metadatas:
        for table in metadata.tables.values():
            schema = table.schema or "public"
            schemas.add(schema)

    existing_schemas = set(
        row[0]
        for row in connection.execute(
            sa.text("SELECT schema_name FROM information_schema.schemata")
        )
    )

    missing_schemas = schemas - existing_schemas
    extra_schemas = (
        existing_schemas
        - schemas
        - {
            "information_schema",
            "public",
            "tiger",  # PostGIS Schemas
            "tiger_data",
            "topology",
        }
        - {x for x in existing_schemas if x.startswith("pg_") or x.startswith("__")}
    )

    if extra_schemas:
        log.warning(
            "⚠️  Warning: The following schemas exist in the database but are not defined in code: %s",
            extra_schemas,
        )

    upgrade_ops = [
        ops.ExecuteSQLOp(sqltext=f"CREATE SCHEMA IF NOT EXISTS {schema};")
        for schema in sorted(missing_schemas)
        if schema != "public"
    ]
    downgrade_ops = [
        ops.ExecuteSQLOp(sqltext=f"DROP SCHEMA IF EXISTS {schema} CASCADE;")
        for schema in sorted(missing_schemas)
        if schema != "public"
    ]
    return upgrade_ops, downgrade_ops


def process_rls_revision_directives(context, revision, directives):
    migration_script, connection, dialect, metadatas = process_revision_directives_base(
        context, revision, directives
    )

    upgrade_ops = []
    downgrade_ops = []

    for metadata in metadatas:
        for table in metadata.tables.values():
            table_upgrade_ops, table_downgrade_ops = rls_policy_ops(
                connection, table, dialect, metadata
            )
            upgrade_ops.extend(table_upgrade_ops)
            downgrade_ops.extend(table_downgrade_ops)

    return upgrade_ops, downgrade_ops


def process_grant_revision_directives(context, revision, directives):
    migration_script, connection, dialect, metadatas = process_revision_directives_base(
        context, revision, directives
    )

    upgrade_ops = []
    downgrade_ops = []

    for metadata in metadatas:
        for table in metadata.tables.values():
            existing_grants = get_existing_grants(
                connection, table.name, schema=table.schema or "public"
            )
            desired_grants = get_grants_for_table_name(table.name, metadata)
            to_grant, to_revoke = diff_simplified_grants(
                existing_grants, desired_grants
            )

            for grant in to_grant:
                grant_sql = f"GRANT {grant.action} ON {table.schema}.{table.name} TO {grant.role};"
                upgrade_ops.append(ops.ExecuteSQLOp(sqltext=grant_sql))
                revoke_sql = f"REVOKE {grant.action} ON {table.schema}.{table.name} FROM {grant.role};"
                downgrade_ops.append(ops.ExecuteSQLOp(sqltext=revoke_sql))

            for grant in to_revoke:
                revoke_sql = f"REVOKE {grant.action} ON {table.schema}.{table.name} FROM {grant.role};"
                upgrade_ops.append(ops.ExecuteSQLOp(sqltext=revoke_sql))
                grant_sql = f"GRANT {grant.action} ON {table.schema}.{table.name} TO {grant.role};"
                downgrade_ops.append(ops.ExecuteSQLOp(sqltext=grant_sql))

            sequence_grant_up, sequence_grant_down = get_sequence_grants(
                table, desired_grants
            )
            upgrade_ops.extend(sequence_grant_up)
            downgrade_ops.extend(sequence_grant_down)

    return upgrade_ops, downgrade_ops


def get_sequence_grants(table: sa.Table, grants: list[Grant]) -> tuple[list, list]:
    upgrade_ops = []
    downgrade_ops = []

    sequence_names = find_sequence_names(table)
    print("SEQUENCE NAMES", sequence_names)

    for seq_name in sequence_names:
        for grant in grants:
            upgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"GRANT USAGE, SELECT ON SEQUENCE {seq_name} TO {grant.role};"
                )
            )
            downgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"REVOKE USAGE, SELECT ON SEQUENCE {seq_name} FROM {grant.role};"
                )
            )

    return upgrade_ops, downgrade_ops


def process_grant_schema_revision_directives(context, revision, directives):
    migration_script, connection, dialect, metadatas = process_revision_directives_base(
        context, revision, directives
    )

    upgrade_ops = []
    downgrade_ops = []

    schema_roles = defaultdict(set)

    for metadata in metadatas:
        for table in metadata.tables.values():
            schema = table.schema or "public"

            desired_grants = get_grants_for_table_name(table.name, metadata)
            for grant in desired_grants:
                schema_roles[schema].add(grant.role)

    for schema, roles in schema_roles.items():
        for role in roles:
            schema_exists = connection.execute(
                sa.text("""
                    SELECT 1 FROM information_schema.schemata WHERE schema_name = :schema
                """),
                {"schema": schema},
            ).scalar()

            existing_roles = set()
            if schema_exists:
                # Check if the role already has USAGE on the schema
                try:
                    existing_usage = connection.execute(
                        sa.text("""
                        SELECT has_schema_privilege(:role, :schema, 'USAGE') AS has_usage
                        """),
                        {"role": role, "schema": schema},
                    ).scalar()
                except sa.exc.ProgrammingError as e:
                    print(e)
                    if "InvalidSchemaName" in str(e):
                        existing_usage = False

                if existing_usage:
                    existing_roles.add(role)

            if role not in existing_roles:
                grant_sql = f"GRANT USAGE ON SCHEMA {schema} TO {role};"
                upgrade_ops.append(ops.ExecuteSQLOp(sqltext=grant_sql))
                revoke_sql = f"REVOKE USAGE ON SCHEMA {schema} FROM {role};"
                downgrade_ops.append(ops.ExecuteSQLOp(sqltext=revoke_sql))

    return upgrade_ops, downgrade_ops


def rls_policy_ops(connection, table, dialect, metadata):
    desired = {x.name: x for x in get_policies_for_table_name(table.name, metadata)}
    existing = {
        x.name: x for x in get_existing_policies_as_objects(connection, table, dialect)
    }

    to_create, to_replace, to_drop = diff_rls_policies(
        existing.values(), desired.values()
    )

    upgrade_ops = []
    downgrade_ops = []
    full_table = f"{table.schema or 'public'}.{table.name}"

    if len(desired):
        has_rls = connection.execute(
            sa.text("""
            SELECT relrowsecurity
            FROM pg_class
            JOIN pg_namespace ON pg_class.relnamespace = pg_namespace.oid
            WHERE relname = :table AND nspname = :schema
        """),
            {"table": table.name, "schema": table.schema},
        ).scalar()

        if not has_rls:
            upgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"ALTER TABLE {full_table} ENABLE ROW LEVEL SECURITY;"
                )
            )

            downgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"ALTER TABLE {full_table} DISABLE ROW LEVEL SECURITY;"
                )
            )
    elif len(existing):
        upgrade_ops.append(
            ops.ExecuteSQLOp(
                sqltext=f"ALTER TABLE {full_table} DISABLE ROW LEVEL SECURITY;"
            )
        )

        downgrade_ops.append(
            ops.ExecuteSQLOp(
                sqltext=f"ALTER TABLE {full_table} ENABLE ROW LEVEL SECURITY;"
            )
        )

    for name in to_create:
        upgrade_ops.append(ops.ExecuteSQLOp(sqltext=desired[name].compile(dialect)))
        downgrade_ops.append(
            ops.ExecuteSQLOp(sqltext=f"DROP POLICY IF EXISTS {name} ON {full_table};")
        )

    for name in to_replace:
        upgrade_ops.append(
            ops.ExecuteSQLOp(sqltext=f"DROP POLICY IF EXISTS {name} ON {full_table};")
        )
        upgrade_ops.append(ops.ExecuteSQLOp(sqltext=desired[name].compile(dialect)))

        downgrade_ops.append(
            ops.ExecuteSQLOp(sqltext=f"DROP POLICY IF EXISTS {name} ON {full_table};")
        )
        downgrade_ops.append(ops.ExecuteSQLOp(sqltext=desired[name].compile(dialect)))

    for name in to_drop:
        upgrade_ops.append(
            ops.ExecuteSQLOp(sqltext=f"DROP POLICY IF EXISTS {name} ON {full_table};")
        )
        downgrade_ops.append(ops.ExecuteSQLOp(sqltext=existing[name].compile(dialect)))

    return upgrade_ops, downgrade_ops
