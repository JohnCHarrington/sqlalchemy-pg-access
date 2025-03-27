from sqlalchemy import Column, Integer, Table, func
from sqlalchemy.dialects.postgresql import dialect as pg_dialect

from sqlalchemy_pg_access.policy import RLSPolicy


def test_rls_policy_compile_basic(metadata):
    table = Table("my_table", metadata, Column("owner_id", Integer))
    
    policy = RLSPolicy(
        table=table,
        name="p_read",
        commands=["SELECT"],
        roles=["user"],
    )
    policy.using_clause = table.c.owner_id == func.current_setting("app.current_user_id").cast(Integer)

    compiled_sql = policy.compile(dialect=pg_dialect())
    
    assert "CREATE POLICY p_read ON my_table" in compiled_sql
    assert "USING" in compiled_sql
    assert "current_setting" in compiled_sql
