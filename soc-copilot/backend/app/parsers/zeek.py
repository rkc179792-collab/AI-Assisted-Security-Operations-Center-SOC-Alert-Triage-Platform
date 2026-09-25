from datetime import datetime, timezone
from typing import Any

from app.models.alert import AlertSource, NormalizedAlert, Severity
from app.parsers.base import AlertParser


# Zeek's notice.log has no numeric severity field, so we bucket by the
# "note" type instead. Scans and generic activity are noisy background
# noise; these prefixes indicate something worth a human looking at sooner.
HIGH_SEVERITY_NOTE_PREFIXES = ("Malware::", "Intel::", "SSL::Invalid_Server_Cert")


class ZeekParser(AlertParser):
    """Parses Zeek notice.log records emitted as JSON (LogAscii::use_json=T)."""

    def parse(self, payload: dict[str, Any]) -> NormalizedAlert:
        note = payload.get("note", "unknown-notice")
        severity = (
            Severity.HIGH if note.startswith(HIGH_SEVERITY_NOTE_PREFIXES) else Severity.MEDIUM
        )

        return NormalizedAlert(
            timestamp=datetime.fromtimestamp(float(payload.get("ts", 0)), tz=timezone.utc),
            source=AlertSource.ZEEK,
            severity=severity,
            rule_name=note,
            description=payload.get("msg", "No description provided"),
            src_ip=payload.get("id.orig_h") or payload.get("src"),
            dst_ip=payload.get("id.resp_h"),
            mitre_techniques=[],
            raw=payload,
        )
