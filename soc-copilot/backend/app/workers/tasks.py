import asyncio

import structlog

from app.db.base import SessionLocal
from app.db.repository import save_alert
from app.enrichment.pipeline import enrich_alert
from app.models.alert import NormalizedAlert
from app.notifications.slack import notify_if_critical

log = structlog.get_logger()


def process_alert(alert: NormalizedAlert) -> None:
    """RQ entrypoint — this is what the worker process actually calls.

    RQ workers are synchronous, but the pipeline underneath is async (httpx
    calls to VirusTotal and Slack, an async DB session). Rather than making
    the whole worker async, we open one event loop per job here and run the
    real logic inside it.
    """
    asyncio.run(_process_alert_async(alert))


async def _process_alert_async(alert: NormalizedAlert) -> None:
    try:
        await enrich_alert(alert)

        async with SessionLocal() as session:
            await save_alert(session, alert)

        await notify_if_critical(alert)

        log.info(
            "alert.processed",
            alert_id=str(alert.id),
            source=alert.source.value,
            indicators=len(alert.indicators),
        )
    except Exception as exc:
        log.error("alert.processing_failed", alert_id=str(alert.id), error=str(exc))
        # Re-raise so RQ records this as a failed job instead of a silent
        # success. Failed jobs land in the failed job registry and can be
        # requeued with `rq requeue` once the underlying issue is fixed.
        raise
