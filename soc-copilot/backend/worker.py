"""RQ worker entrypoint.

Run with:  python worker.py
Or, under Docker Compose, this is the `worker` service's command.
"""
from rq import Worker

from app.workers.queue import alert_queue, redis_conn

if __name__ == "__main__":
    worker = Worker([alert_queue], connection=redis_conn)
    worker.work()
