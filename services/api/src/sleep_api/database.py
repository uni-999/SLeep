import os
from collections.abc import Generator

from sqlalchemy import URL, create_engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


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


DATABASE_URL = database_url()


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session
