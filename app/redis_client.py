"""Redis connection pool."""
import redis.asyncio as aioredis
from app.config import get_settings

settings = get_settings()

redis_pool = aioredis.ConnectionPool.from_url(
    settings.REDIS_URL,
    max_connections=20,
    decode_responses=True,
)

async def get_redis():
    return aioredis.Redis(connection_pool=redis_pool)
