from datetime import datetime
from typing import Any

from app.models.alert import AlertSource, NormalizedAlert, Severity
from app.parsers.base import AlertParser


SEVERITY_VALUES = {s.value: s for s in Severity}


class GenericParser(AlertParser):
    """Handles the simple {timestamp, severity, ...} shape used in tests and demos."""

    def parse(self, payload: dict[str, Any]) -> NormalizedAlert:
        raw_sev = str(payload.get("severity", "info")).lower()
        severity = SEVERITY_VALUES.get(raw_sev, Severity.INFO)

        return NormalizedAlert(
            timestamp=datetime.fromisoformat(
                payload.get("timestamp", datetime.utcnow().isoformat())
            ),
            source=AlertSource.GENERIC,
            severity=severity,
            rule_name=payload.get("rule_name", "generic-rule"),
            description=payload.get("description", ""),
            src_ip=payload.get("src_ip"),
            dst_ip=payload.get("dst_ip"),
            src_user=payload.get("src_user"),
            hostname=payload.get("hostname"),
            process=payload.get("process"),
            mitre_techniques=payload.get("mitre_techniques", []),
            raw=payload,
        )
