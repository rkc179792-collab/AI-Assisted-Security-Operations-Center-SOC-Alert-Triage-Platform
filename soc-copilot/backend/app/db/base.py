from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

ASYNC_DATABASE_URL = settings.database_url.replace(
    "postgresql://", "postgresql+asyncpg://", 1
)

engine = create_async_engine(ASYNC_DATABASE_URL, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_session():
    async with SessionLocal() as session:
        yield session
