import re
from typing import Iterable

from app.models.alert import Indicator, NormalizedAlert


# Deliberately narrow patterns: fewer false positives means fewer wasted API calls.
IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|top|xyz|info|biz)\b",
    re.IGNORECASE,
)

# Reserved ranges we never want to query.
PRIVATE_NET = re.compile(
    r"^(10\.|127\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.)"
)


def _iter_strings(alert: NormalizedAlert) -> Iterable[str]:
    """Yield every text field worth scanning for indicators."""
    for field in ("description", "process", "src_user", "hostname"):
        if value := getattr(alert, field):
            yield value
    # Raw payload can be huge; serialize it to text and scan once.
    yield str(alert.raw)


def extract_indicators(alert: NormalizedAlert) -> list[Indicator]:
    """Pull unique IOCs out of an alert's text fields."""
    seen: set[str] = set()
    indicators: list[Indicator] = []

    for text in _iter_strings(alert):
        for match in SHA256_RE.findall(text):
            if match.lower() not in seen:
                seen.add(match.lower())
                indicators.append(Indicator(kind="hash", value=match.lower()))

        for match in MD5_RE.findall(text):
            if match.lower() not in seen:
                seen.add(match.lower())
                indicators.append(Indicator(kind="hash", value=match.lower()))

        for match in IPV4_RE.findall(text):
            if match in seen or PRIVATE_NET.match(match):
                continue
            seen.add(match)
            indicators.append(Indicator(kind="ip", value=match))

        for match in DOMAIN_RE.findall(text):
            if match.lower() not in seen:
                seen.add(match.lower())
                indicators.append(Indicator(kind="domain", value=match.lower()))

    return indicators
