import logging
from collections import defaultdict

import sqlalchemy as sa

from sqlalchemy_pg_access.grant import (
    diff_simplified_grants,
    get_existing_grants,
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


def get_existing_policies(connection, table_name, schema="public"):
    query = """
    SELECT
        pol.polname AS name,
        pol.polcmd AS command,
        pol.polroles AS role_oids,
        pg_get_expr(pol.polqual, pol.polrelid) AS using_clause,
        pg_get_expr(pol.polwithcheck, pol.polrelid) AS with_check_clause
    FROM pg_policy pol
    JOIN pg_class cls ON pol.polrelid = cls.oid
    JOIN pg_namespace ns ON cls.relnamespace = ns.oid
    WHERE cls.relname = :table_name AND ns.nspname = :schema;
    """
    result = connection.execute(
        sa.text(query), {"table_name": table_name, "schema": schema}
    )
    rows = result.fetchall()

    if len(rows):
        # Resolve role OIDs to names
        role_map = {
            row["oid"]: row["rolname"]
            for row in connection.execute(
                sa.text("SELECT oid, rolname FROM pg_roles")
            ).fetchall()
        }

    policies = []
    for row in rows:
        roles = [role_map.get(oid, f"<unknown:{oid}>") for oid in row["role_oids"]]
        policies.append(
            {
                "name": row["name"],
                "command": row["command"],
                "roles": sorted(roles),
                "using": row["using_clause"] or "",
                "check": row["with_check_clause"] or "",
            }
        )
    return policies


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
            migration_script.downgrade_ops.ops.extend(grant_schema_down)

        if grant_permissions:
            grant_up, grant_down = process_grant_revision_directives(
                context, revision, directives
            )
            migration_script.upgrade_ops.ops.extend(grant_up)
            migration_script.downgrade_ops.ops.extend(grant_down)

        if rls:
            rls_up, rls_down = process_rls_revision_directives(
                context, revision, directives
            )
            migration_script.upgrade_ops.ops.extend(rls_up)
            migration_script.downgrade_ops.ops.extend(rls_down)

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
            table_upgrade_ops, table_downgrade_ops = diff_rls_policies_for_table(
                connection,
                table,
                get_policies_for_table_name(table.name, metadata),
                dialect,
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
                grant_sql = f"GRANT {', '.join(grant.actions)} ON {table.name} TO {', '.join(grant.roles)};"
                upgrade_ops.append(ops.ExecuteSQLOp(sqltext=grant_sql))
                revoke_sql = f"REVOKE {', '.join(grant.actions)} ON {table.name} FROM {', '.join(grant.roles)};"
                downgrade_ops.append(ops.ExecuteSQLOp(sqltext=revoke_sql))

            for grant in to_revoke:
                revoke_sql = f"REVOKE {', '.join(grant.actions)} ON {table.name} FROM {', '.join(grant.roles)};"
                upgrade_ops.append(ops.ExecuteSQLOp(sqltext=revoke_sql))
                grant_sql = f"GRANT {', '.join(grant.actions)} ON {table.name} TO {', '.join(grant.roles)};"
                downgrade_ops.append(ops.ExecuteSQLOp(sqltext=grant_sql))

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
                schema_roles[schema].update(grant.roles)

    for schema, roles in schema_roles.items():
        schema_exists = connection.execute(
            sa.text("""
                SELECT 1 FROM information_schema.schemata WHERE schema_name = :schema
            """),
            {"schema": schema},
        ).scalar()

        existing_roles = set()
        if schema_exists:
            for role in roles:
                # Check if the role already has USAGE on the schema
                try:
                    existing_usage = connection.execute(
                        sa.text("""
                        SELECT has_schema_privilege(:role, :schema, 'USAGE') AS has_usage
                        """),
                        {"role": role, "schema": schema},
                    ).scalar()
                except sa.exc.ProgrammingError as e:
                    if "InvalidSchemaName" in str(e):
                        existing_usage = False

                if existing_usage:
                    existing_roles.add(role)

        new_roles = roles - existing_roles

        if new_roles:
            grant_sql = f"GRANT USAGE ON SCHEMA {schema} TO {', '.join(new_roles)};"
            upgrade_ops.append(ops.ExecuteSQLOp(sqltext=grant_sql))
            revoke_sql = f"REVOKE USAGE ON SCHEMA {schema} FROM {', '.join(new_roles)};"
            downgrade_ops.append(ops.ExecuteSQLOp(sqltext=revoke_sql))

    return upgrade_ops, downgrade_ops


def rls_policy_signature(policy):
    return {
        "name": policy.name,
        "commands": [x.upper() for x in policy.commands] if policy.commands else [],
        "roles": sorted(policy.roles) if policy.roles else [],
        "using": str(policy.using_clause or ""),
        "check": str(policy.with_check_clause or ""),
    }


def diff_rls_policies_for_table(connection, table, desired_policies, dialect):
    upgrade_ops = []
    downgrade_ops = []

    existing_policies = get_existing_policies(
        connection, table.name, schema=table.schema or "public"
    )
    existing_by_name = {p["name"]: p for p in existing_policies}
    desired_by_name = {p.name: rls_policy_signature(p) for p in desired_policies}
    desired_by_key = {p.name: p for p in desired_policies}

    # Add or update
    for name, desired in desired_by_name.items():
        if name not in existing_by_name:
            # New policy
            create = desired_by_key[name].compile(
                dialect=dialect, compile_kwargs={"literal_binds": True}
            )
            upgrade_ops.append(ops.ExecuteSQLOp(sqltext=create))
            downgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"DROP POLICY IF EXISTS {name} ON {table.name};"
                )
            )
        elif desired != existing_by_name[name]:
            # Changed: drop + recreate
            create = desired_by_key[name].compile(
                dialect=dialect, compile_kwargs={"literal_binds": True}
            )
            upgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"DROP POLICY IF EXISTS {name} ON {table.name};"
                )
            )
            upgrade_ops.append(ops.ExecuteSQLOp(sqltext=create))

            # Revert = recreate the old one
            existing = existing_by_name[name]
            using_clause = f" USING ({existing['using']})" if existing["using"] else ""
            with_check = (
                f" WITH CHECK ({existing['check']})" if existing["check"] else ""
            )
            roles = ", ".join(existing["roles"])
            recreate_sql = (
                f"CREATE POLICY {name} ON {table.name} "
                f"FOR {existing['command']} TO {roles}{using_clause}{with_check};"
            )
            downgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"DROP POLICY IF EXISTS {name} ON {table.name};"
                )
            )
            downgrade_ops.append(ops.ExecuteSQLOp(sqltext=recreate_sql))

    # Drop removed
    for name in existing_by_name:
        if name not in desired_by_name:
            upgrade_ops.append(
                ops.ExecuteSQLOp(
                    sqltext=f"DROP POLICY IF EXISTS {name} ON {table.name};"
                )
            )

            # Recreate in downgrade
            existing = existing_by_name[name]
            using_clause = f" USING ({existing['using']})" if existing["using"] else ""
            with_check = (
                f" WITH CHECK ({existing['check']})" if existing["check"] else ""
            )
            roles = ", ".join(existing["roles"])
            recreate_sql = (
                f"CREATE POLICY {name} ON {table.name} "
                f"FOR {existing['command']} TO {roles}{using_clause}{with_check};"
            )
            downgrade_ops.append(ops.ExecuteSQLOp(sqltext=recreate_sql))

    return upgrade_ops, downgrade_ops
