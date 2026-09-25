import httpx
import structlog

from app.core.config import settings
from app.models.alert import Indicator


log = structlog.get_logger()
VT_BASE = "https://www.virustotal.com/api/v3"


async def enrich_with_virustotal(indicator: Indicator) -> Indicator:
    """Look up an indicator on VirusTotal. Returns the indicator, enriched."""

    if not settings.virustotal_api_key:
        return indicator

    endpoint = _endpoint_for(indicator)
    if endpoint is None:
        return indicator

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{VT_BASE}/{endpoint}",
                headers={"x-apikey": settings.virustotal_api_key},
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        log.warning("virustotal.lookup_failed", value=indicator.value, error=str(exc))
        return indicator

    stats = (
        data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) or 1

    indicator.score = int((malicious + suspicious) / total * 100)
    indicator.source = "virustotal"
    indicator.details = stats

    if malicious >= 5:
        indicator.verdict = "malicious"
    elif malicious + suspicious >= 2:
        indicator.verdict = "suspicious"
    else:
        indicator.verdict = "clean"

    return indicator


def _endpoint_for(indicator: Indicator) -> str | None:
    match indicator.kind:
        case "ip":
            return f"ip_addresses/{indicator.value}"
        case "domain":
            return f"domains/{indicator.value}"
        case "hash":
            return f"files/{indicator.value}"
        case _:
            return None
