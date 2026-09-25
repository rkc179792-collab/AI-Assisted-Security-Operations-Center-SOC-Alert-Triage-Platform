import redis
from rq import Queue

from app.core.config import settings

redis_conn = redis.from_url(settings.redis_url)
alert_queue = Queue("alerts", connection=redis_conn)
