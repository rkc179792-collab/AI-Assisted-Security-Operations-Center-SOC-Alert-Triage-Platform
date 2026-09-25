from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_session
from app.db.repository import recent_alerts

router = APIRouter()


@router.get("/alerts")
async def list_alerts(session: AsyncSession = Depends(get_session)):
    records = await recent_alerts(session)
    return [
        {
            "id": str(r.id),
            "timestamp": r.timestamp.isoformat(),
            "source": r.source,
            "severity": r.severity,
            "rule_name": r.rule_name,
            "hostname": r.hostname,
            "src_ip": r.src_ip,
            "mitre_techniques": r.mitre_techniques,
            "indicators": [
                {"kind": i.kind, "value": i.value, "verdict": i.verdict}
                for i in r.indicators
            ],
        }
        for r in records
    ]
