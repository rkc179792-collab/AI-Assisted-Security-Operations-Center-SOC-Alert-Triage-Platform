from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertSource(str, Enum):
    WAZUH = "wazuh"
    SURICATA = "suricata"
    ZEEK = "zeek"
    GENERIC = "generic"


class Indicator(BaseModel):
    """A single piece of threat intelligence."""
    kind: str          # "ip", "domain", "hash", "url"
    value: str
    verdict: str = "unknown"   # "malicious", "suspicious", "clean", "unknown"
    score: int | None = None   # 0-100 from the provider
    source: str | None = None  # "virustotal", "abuseipdb", etc.
    details: dict[str, Any] = Field(default_factory=dict)


class NormalizedAlert(BaseModel):
    """Canonical alert shape. Every parser produces one of these."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source: AlertSource
    severity: Severity
    rule_name: str
    description: str

    src_ip: str | None = None
    dst_ip: str | None = None
    src_user: str | None = None
    hostname: str | None = None
    process: str | None = None

    mitre_techniques: list[str] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
