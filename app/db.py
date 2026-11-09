from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase

from .config import settings


class Base(DeclarativeBase):
    pass


database_url = make_url(settings.database_url)
connect_args = {}
if database_url.drivername in {"postgres", "postgresql"}:
    database_url = database_url.set(drivername="postgresql+asyncpg")
if database_url.drivername == "postgresql+asyncpg":
    query = dict(database_url.query)
    sslmode = query.pop("sslmode", None)
    query.pop("channel_binding", None)
    database_url = database_url.set(query=query)
    if sslmode == "require":
        connect_args["ssl"] = "require"

engine = create_async_engine(
    database_url,
    pool_pre_ping=True,
    connect_args=connect_args,
)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


async def create_schema() -> None:
    from . import models  # noqa: F401

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)


async def dispose_db() -> None:
    await engine.dispose()