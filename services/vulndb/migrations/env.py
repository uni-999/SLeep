"""Alembic environment for the vulnerability knowledge base.

On PostgreSQL every table, including Alembic's own version table, lives in the
``vulndb`` schema, so this history is independent from the API's history in
``public`` and autogenerate never looks at the API's tables. On SQLite, which
has no schemas, the schema name is dropped.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import BLANK_SCHEMA, MetaData, pool, text

from sleep_vulndb import db_models  # noqa: F401
from sleep_vulndb.database import SCHEMA, Base, database_url, make_engine, uses_schemas


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

DATABASE_URL = database_url()
WITH_SCHEMAS = uses_schemas(DATABASE_URL)


def target_metadata() -> MetaData:
    if WITH_SCHEMAS:
        return Base.metadata
    metadata = MetaData()
    for table in Base.metadata.sorted_tables:
        # schema=None takes the (empty) schema of the new MetaData; foreign keys
        # must be re-pointed explicitly, otherwise they still say "vulndb.".
        table.to_metadata(metadata, schema=None, referred_schema_fn=lambda *_: BLANK_SCHEMA)
    return metadata


def include_name(name: str | None, type_: str, _parent_names: object) -> bool:
    # On PostgreSQL compare only our schema, never the API's tables in public.
    if type_ == "schema" and WITH_SCHEMAS:
        return name == SCHEMA
    return True


def configure(**kwargs: object) -> None:
    context.configure(
        target_metadata=target_metadata(),
        compare_type=True,
        version_table_schema=SCHEMA if WITH_SCHEMAS else None,
        include_schemas=WITH_SCHEMAS,
        include_name=include_name,
        **kwargs,
    )


def run_migrations_offline() -> None:
    configure(url=DATABASE_URL, literal_binds=True, dialect_opts={"paramstyle": "named"})
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = make_engine(DATABASE_URL, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        if WITH_SCHEMAS:
            # The version table is created inside the schema, so it must exist first.
            # In the Compose stack deploy/postgres/vulndb-role.sql has already created
            # it for the service role, which may not create schemas: even
            # CREATE SCHEMA IF NOT EXISTS needs that right, so check first.
            exists = connection.scalar(text("SELECT 1 FROM pg_namespace WHERE nspname = :name"), {"name": SCHEMA})
            if not exists:
                connection.execute(text(f'CREATE SCHEMA "{SCHEMA}"'))
            connection.commit()
        configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
