from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AlertRecord, IndicatorRecord
from app.models.alert import NormalizedAlert


async def save_alert(session: AsyncSession, alert: NormalizedAlert) -> None:
    """Persist one fully enriched alert. Call this once, after enrichment,
    not before — we want the indicators written in the same row insert."""

    record = AlertRecord(
        id=alert.id,
        timestamp=alert.timestamp,
        source=alert.source.value,
        severity=alert.severity.value,
        rule_name=alert.rule_name,
        description=alert.description,
        src_ip=alert.src_ip,
        dst_ip=alert.dst_ip,
        src_user=alert.src_user,
        hostname=alert.hostname,
        process=alert.process,
        mitre_techniques=alert.mitre_techniques,
        raw=alert.raw,
        indicators=[
            IndicatorRecord(
                kind=i.kind,
                value=i.value,
                verdict=i.verdict,
                score=i.score,
                source=i.source,
            )
            for i in alert.indicators
        ],
    )
    session.add(record)
    await session.commit()


async def recent_alerts(session: AsyncSession, limit: int = 50) -> list[AlertRecord]:
    result = await session.execute(
        select(AlertRecord).order_by(AlertRecord.timestamp.desc()).limit(limit)
    )
    return list(result.scalars().all())
