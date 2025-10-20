import os
import logging
from typing import Optional
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
import redis.asyncio as redis

# Экспортируемые объекты
engine = None
AsyncSessionLocal: Optional[async_sessionmaker[AsyncSession]] = None
redis_client: Optional[redis.Redis] = None

logger = logging.getLogger(__name__)


async def create_engine_with_retry(url):
    # Минимальная инициализация async-движка
    return create_async_engine(url, pool_pre_ping=True)


async def init_db_connections():
    global engine, AsyncSessionLocal, redis_client

    db_url = os.getenv('DB_URL')
    if not db_url:
        raise ValueError("DB_URL не задан в env vars!")

    redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    redis_password = os.getenv('REDIS_PASSWORD')

    engine = await create_engine_with_retry(db_url)
    AsyncSessionLocal = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )

    redis_params = {'decode_responses': True}
    if redis_password:
        redis_params['password'] = redis_password
    redis_client = redis.from_url(redis_url, **redis_params)


async def get_db() -> AsyncSession:
    session = AsyncSessionLocal()
    try:
        yield session
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


