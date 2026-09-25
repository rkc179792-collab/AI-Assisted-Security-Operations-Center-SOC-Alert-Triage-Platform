from datetime import datetime
from typing import Any

from app.models.alert import AlertSource, NormalizedAlert, Severity
from app.parsers.base import AlertParser


# Suricata's own scale runs 1 (most severe) to 3 (least severe) — the
# opposite direction from Wazuh's 0-15 scale, so this map is intentionally
# kept separate rather than shared or inverted through a formula.
SEVERITY_MAP = {
    1: Severity.HIGH,
    2: Severity.MEDIUM,
    3: Severity.LOW,
}


class SuricataParser(AlertParser):
    """Parses Suricata eve.json records where event_type == 'alert'."""

    def parse(self, payload: dict[str, Any]) -> NormalizedAlert:
        alert = payload.get("alert", {})
        suricata_severity = int(alert.get("severity", 3))

        return NormalizedAlert(
            timestamp=datetime.fromisoformat(
                self._normalize_timestamp(payload.get("timestamp"))
            ),
            source=AlertSource.SURICATA,
            severity=SEVERITY_MAP.get(suricata_severity, Severity.LOW),
            rule_name=str(alert.get("signature_id", "unknown-signature")),
            description=alert.get("signature", "No description provided"),
            src_ip=payload.get("src_ip"),
            dst_ip=payload.get("dest_ip"),
            hostname=payload.get("host"),
            # Suricata rules don't carry ATT&CK IDs natively (unlike Wazuh's
            # rule.mitre block), so this stays empty until we add a
            # signature-to-technique lookup table.
            mitre_techniques=[],
            raw=payload,
        )

    @staticmethod
    def _normalize_timestamp(value: str | None) -> str:
        if not value:
            return datetime.utcnow().isoformat()
        # eve.json emits offsets like "+0000"; fromisoformat needs "+00:00".
        if len(value) >= 5 and value[-5] in "+-" and value[-3] != ":":
            value = f"{value[:-2]}:{value[-2:]}"
        return value
