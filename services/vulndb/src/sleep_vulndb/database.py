"""Database access for the vulnerability knowledge base.

All tables live in the PostgreSQL schema ``vulndb``. The knowledge base is
global reference data, not tenant data, so it is kept apart from the API's
tables in ``public`` and has its own Alembic history. SQLite has no schemas,
so on SQLite (tests, quick local runs) the schema name is translated away.
"""

import os
from functools import cache

from sqlalchemy import URL, Engine, MetaData, create_engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


SCHEMA = "vulndb"


def database_url() -> URL:
    explicit_url = os.getenv("SLEEP_DATABASE_URL")
    if explicit_url:
        return make_url(explicit_url)

    return URL.create(
        drivername="postgresql+psycopg",
        username=os.getenv("SLEEP_DB_USER", "sleep"),
        password=os.getenv("SLEEP_DB_PASSWORD", "sleep"),
        host=os.getenv("SLEEP_DB_HOST", "localhost"),
        port=int(os.getenv("SLEEP_DB_PORT", "5432")),
        database=os.getenv("SLEEP_DB_NAME", "sleep"),
    )


def uses_schemas(url: URL | str) -> bool:
    return make_url(url).get_backend_name() != "sqlite"


def schema_translate_map(url: URL | str) -> dict[str, str | None] | None:
    return None if uses_schemas(url) else {SCHEMA: None}


def make_engine(url: URL | str, **kwargs: object) -> Engine:
    translate = schema_translate_map(url)
    if translate is not None:
        kwargs.setdefault("execution_options", {"schema_translate_map": translate})
    return create_engine(url, pool_pre_ping=True, **kwargs)


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA)


@cache
def default_engine() -> Engine:
    return make_engine(database_url())


@cache
def default_sessions() -> sessionmaker[Session]:
    return sessionmaker(bind=default_engine(), expire_on_commit=False)
