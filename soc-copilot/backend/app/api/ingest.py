import structlog
from fastapi import APIRouter, Header, HTTPException, Request

from app.core.config import settings
from app.models.alert import AlertSource
from app.parsers import get_parser
from app.workers.queue import alert_queue
from app.workers.tasks import process_alert


router = APIRouter()
log = structlog.get_logger()


@router.post("/webhook/{source}")
async def ingest(
    source: str,
    request: Request,
    x_webhook_secret: str = Header(default=""),
):
    expected = settings.webhook_secrets.get(source)
    if expected is None:
        raise HTTPException(status_code=404, detail=f"unknown source: {source}")
    if x_webhook_secret != expected:
        raise HTTPException(status_code=401, detail="bad webhook secret")

    try:
        alert_source = AlertSource(source)
    except ValueError:
        alert_source = AlertSource.GENERIC

    payload = await request.json()
    parser = get_parser(alert_source)
    alert = parser.parse(payload)

    # Enqueue and return immediately. The RQ worker (worker.py) picks this
    # up, runs enrichment + persistence + notification, and survives an API
    # restart mid-job since the job itself lives in Redis, not memory.
    job = alert_queue.enqueue(process_alert, alert)
    log.info("alert.queued", alert_id=str(alert.id), job_id=job.id)

    return {"status": "queued", "alert_id": str(alert.id), "job_id": job.id}
