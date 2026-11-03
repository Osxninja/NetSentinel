"""
NetSentinel - Database Connection & Engine Factory
Author: Hardik
Developer / Organization: Hidden Eye Security

Configures async SQLAlchemy engine with aiosqlite and enforces SQLite WAL PRAGMAs.
"""

__author__ = "Hardik"
__organization__ = "Hidden Eye Security"

from typing import Optional, AsyncGenerator
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from config import settings, NetSentinelConfig
from database.models import Base


def configure_pragmas(engine: AsyncEngine, cfg: Optional[NetSentinelConfig] = None) -> None:
    """
    Registers an event listener on the engine's sync_engine to execute WAL PRAGMAs
    immediately upon acquiring a new raw SQLite DB-API connection.
    """
    c = cfg or settings

    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragmas(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f"PRAGMA journal_mode={c.SQLITE_JOURNAL_MODE};")
        cursor.execute(f"PRAGMA synchronous={c.SQLITE_SYNCHRONOUS};")
        cursor.execute(f"PRAGMA busy_timeout={c.SQLITE_BUSY_TIMEOUT};")
        cursor.execute(f"PRAGMA temp_store={c.SQLITE_TEMP_STORE};")
        cursor.execute(f"PRAGMA wal_autocheckpoint={c.SQLITE_WAL_AUTOCHECKPOINT};")
        cursor.close()


def get_async_engine(
    db_url: Optional[str] = None,
    echo: bool = False,
    cfg: Optional[NetSentinelConfig] = None
) -> AsyncEngine:
    """
    Creates and configures an asynchronous SQLAlchemy engine.
    """
    url = db_url or (cfg.DATABASE_URL if cfg else settings.DATABASE_URL)
    engine = create_async_engine(url, echo=echo, future=True)
    configure_pragmas(engine, cfg)
    return engine


def get_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """
    Returns an async sessionmaker for the given engine with expire_on_commit=False.
    """
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def init_db(engine: AsyncEngine) -> None:
    """
    Initializes database schema asynchronously and applies non-destructive schema migrations.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        def _migrate_schema(sync_conn):
            res = sync_conn.execute(text("PRAGMA table_info(alerts)"))
            cols = [row[1] for row in res.fetchall()]
            if cols and "investigation_report" not in cols:
                sync_conn.execute(text("ALTER TABLE alerts ADD COLUMN investigation_report TEXT"))

        await conn.run_sync(_migrate_schema)


async def get_db_session(engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """
    Async context dependency / generator providing a scoped AsyncSession.
    """
    factory = get_session_factory(engine)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
