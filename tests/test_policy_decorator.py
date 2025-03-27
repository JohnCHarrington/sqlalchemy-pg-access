from sqlalchemy import Integer, func
from sqlmodel import Field, SQLModel

from sqlalchemy_pg_access.policy import rls_policy
from sqlalchemy_pg_access.registry import get_policies_for_model


@rls_policy(
    name="user_read",
    commands=["SELECT"],
    roles=["user"],
    using=lambda cls: cls.user_id == func.current_setting("app.current_user_id").cast(Integer)
)
class MyModel(SQLModel, table=True):
    id: int = Field(primary_key=True)
    user_id: int

def test_decorator_registers_policy():
    policies = get_policies_for_model(MyModel)
    assert len(policies) == 1

    policy = policies[0]
    assert policy.name == "user_read"
    assert policy.commands == ["SELECT"]
    assert "current_setting" in policy.compile()
