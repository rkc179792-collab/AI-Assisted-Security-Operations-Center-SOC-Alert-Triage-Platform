import asyncio

from app.enrichment.ioc import extract_indicators
from app.enrichment.virustotal import enrich_with_virustotal
from app.models.alert import NormalizedAlert


async def enrich_alert(alert: NormalizedAlert) -> NormalizedAlert:
    """Extract IOCs and enrich them in parallel. Never blocks on failure."""

    indicators = extract_indicators(alert)
    if not indicators:
        return alert

    enriched = await asyncio.gather(
        *(enrich_with_virustotal(i) for i in indicators),
        return_exceptions=False,
    )

    alert.indicators = list(enriched)
    return alert
