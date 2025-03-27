# sqlalchemy-pg-access

> ⚠️ **Disclaimer:** I built this super fast, so a lot of it is written by ChatGPT, including this README! Take care in use, and any contributions are welcome.

**Declarative access control for PostgreSQL using SQLAlchemy.**

This package lets you define PostgreSQL RLS policies, GRANT permissions, and schema-level access directly in your SQLAlchemy models — with full Alembic autogeneration support.

---

## ✨ Features

- ✅ Define PostgreSQL `CREATE POLICY` (RLS) in Python
- ✅ Automatically `GRANT` table-level permissions to roles
- ✅ Automatically `GRANT USAGE` on schemas
- ✅ Automatically `CREATE SCHEMA` if missing
- ✅ Intelligent diffs: only emit changed or missing policies and grants
- ✅ Alembic integration with clean upgrade/downgrade support

Warning: This package cannot currently diff policy using/with_check - If you change a policy, rename it!

---

## 📦 Installation

### Core only

```bash
uv pip install sqlalchemy-pg-access
```

### With Alembic integration

```bash
uv pip install sqlalchemy-pg-access[alembic]
```

---

## 🧱 Usage

### 🔐 Define a Row-Level Security (RLS) Policy

```python
from sqlalchemy import func
from sqlmodel import SQLModel, Field
from sqlalchemy_pg_access.decorators import rls_policy

@rls_policy(
    name="read_policy",
    command="SELECT",
    roles=["app_user"],
    using=lambda cls: cls.owner_id == func.current_setting("app.current_user_id").cast(int)
)
class MyTable(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
```

---

### 🔓 Grant Permissions to Roles

```python
from sqlalchemy_pg_access.decorators import grant_permissions

@grant_permissions(["SELECT", "UPDATE"], to=["app_user", "readonly"])
class MyTable(SQLModel, table=True):
    ...
```

---

### 🏗️ Automatically Create Schemas

When a model uses a custom schema:

```python

@grant_permissions(["SELECT"], to=["app_user"])
class MyTable(SQLModel, table=True):
    __tablename__ = "my_table"
    __table_args__ = {"schema": "my_schema"}
```

The migration will:

- Create `my_schema` if it doesn't exist
- Grant `USAGE` on `my_schema` to app_user
- Grant `SELECT` on `my_table` to app_user

---

## ⚙️ Alembic Integration

### 1. Enable in `env.py`

```python
from sqlalchemy_pg_access.alembic import generate_process_revision_directives

context.configure(
    ...,
    process_revision_directives=generate_process_revision_directives(
        rls=True, schema=True, grant_permissions=True, grant_schema_permissions=True
    ),
)
```

### 2. Autogenerate a migration

```bash
alembic revision --autogenerate -m "Add RLS and access controls"
```

Alembic will generate:

- `CREATE SCHEMA` if needed
- `GRANT USAGE ON SCHEMA ...`
- `GRANT ... ON TABLE ...`
- `CREATE POLICY ...`
- Full `REVOKE` / `DROP POLICY` for downgrades

---

## 🛠 Requirements

- Python 3.10+
- `sqlalchemy >= 2.0`
- `alembic >= 1.12` (optional)
- Supports `sqlmodel`, `declarative_base`, or plain SQLAlchemy tables

---

## 🧪 Roadmap

- [ ] Optional: `CREATE ROLE` and `GRANT ROLE` management
- [ ] `ALTER POLICY` diffs
- [ ] Policy templates or reusables
- [ ] CLI tool for auditing access control state

---

## 📄 License

MIT

---

## 💬 Feedback

Open an issue or pull request — feedback and contributions are very welcome!
