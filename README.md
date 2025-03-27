# sqlalchemy-pg-access

PostgreSQL Row-Level Security (RLS) integration for SQLAlchemy, with optional Alembic autogeneration support.

---

## ✨ Features

- ✅ Define Postgres RLS policies declaratively using decorators on sqlalchemy/sqlmodel classes
- ✅ Optional Alembic integration via `[alembic]` extra
- ✅ Automatic `CREATE POLICY` / `DROP POLICY` generation

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

## 🧱 Defining RLS Policies

### Option 2: `@rls_policy` Decorator

```python
from sqlalchemy_pg_access.policy import rls_policy

@rls_policy(
    name="read_only_own_docs",
    command="SELECT",
    roles=["app_user"],
    using=lambda cls: cls.owner_id == func.current_setting("app.current_user_id").cast(int),
    with_check=lambda cls: cls.owner_id == func.current_setting("app.current_user_id").cast(int)
)
class UserDoc(SQLModel, table=True):
    id: int = Field(primary_key=True)
    owner_id: int
    content: str
```

---

## ⚙️ Alembic Integration

### 1. Enable the autogeneration hook

In your Alembic `env.py`:

```python
from sqlalchemy_pg_access.alembic_support import process_revision_directives

context.configure(
    ...,
    process_revision_directives=process_revision_directives,
)
```

### 2. Generate a migration

```bash
alembic revision --autogenerate -m "Add RLS policies"
```

This will include `op.execute("CREATE POLICY ...")` statements in the migration.

### 3. Downgrade support

Each policy will generate a corresponding `DROP POLICY IF EXISTS` in the `downgrade()` block.

---

## 🔍 How It Works

- RLS policies are defined as SQLAlchemy `SchemaItem`s and compiled via `@compiles(RLSPolicy)`
- They are registered to a global runtime registry
- Alembic picks them up during autogeneration and injects the appropriate DDL

---

## 🧪 Roadmap

- [ ] Policy diffing from live database
- [ ] ALTER POLICY support
- [ ] Policy sets and reusable templates

---

## 📄 License

MIT

---

## 💬 Feedback

Open an issue or pull request on GitHub! Contributions are welcome.
