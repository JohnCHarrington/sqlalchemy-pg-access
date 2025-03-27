from typing import Any

_rls_registry: dict[Any, list["RLSPolicy"]] = {}  # type: ignore # noqa: F821
_grant_registry: dict[Any, list["Grant"]] = {}  # type: ignore # noqa: F821


def register_rls_policy(model_cls, policy: "RLSPolicy") -> None:  # type: ignore # noqa: F821
    _rls_registry.setdefault(model_cls, []).append(policy)


def get_policies_for_model(model_cls) -> list["RLSPolicy"]:  # type: ignore # noqa: F821
    return _rls_registry.get(model_cls, [])


def get_policies_for_table_name(table_name, metadata) -> list["RLSPolicy"]:  # type: ignore # noqa: F821
    for model_cls in _rls_registry:
        if hasattr(model_cls, "__table__"):
            table = model_cls.__table__
            if table.name == table_name and table.metadata is metadata:
                return _rls_registry[model_cls]
    return []


def register_grant(model_cls, grant: "Grant") -> None:  # type: ignore # noqa: F821
    _grant_registry.setdefault(model_cls, []).append(grant)


def get_grants_for_table_name(table_name, metadata) -> list["Grant"]:  # type: ignore # noqa: F821
    for cls, grants in _grant_registry.items():
        if hasattr(cls, "__table__"):
            table = cls.__table__
            if table.name == table_name and table.metadata is metadata:
                return grants
    return []
