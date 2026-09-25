import httpx
import structlog

from app.core.config import settings
from app.models.alert import NormalizedAlert, Severity

log = structlog.get_logger()

NOTIFY_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}


async def notify_if_critical(alert: NormalizedAlert) -> None:
    """Post a Slack message for high/critical alerts. No-op if unconfigured
    or if the alert doesn't clear the severity bar — most alerts shouldn't
    page anyone."""

    if alert.severity not in NOTIFY_SEVERITIES:
        return
    if not settings.slack_webhook_url:
        return

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                settings.slack_webhook_url, json={"text": format_message(alert)}
            )
            response.raise_for_status()
    except httpx.HTTPError as exc:
        # A failed Slack post should never fail the pipeline. By the time
        # we're here the alert is already enriched and saved, so this is
        # best-effort delivery, not the source of truth.
        log.warning("slack.notify_failed", alert_id=str(alert.id), error=str(exc))


def format_message(alert: NormalizedAlert) -> str:
    malicious = [i.value for i in alert.indicators if i.verdict == "malicious"]
    ioc_line = ", ".join(malicious) if malicious else "none confirmed"

    return (
        f"*[{alert.severity.value.upper()}]* {alert.rule_name} on "
        f"`{alert.hostname or 'unknown host'}`\n"
        f"{alert.description}\n"
        f"IOCs: {ioc_line}"
    )
