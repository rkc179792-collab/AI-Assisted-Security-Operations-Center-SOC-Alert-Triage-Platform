from datetime import timedelta

from app.models.alert import NormalizedAlert


CORRELATION_WINDOW = timedelta(minutes=30)


def _entities(alert: NormalizedAlert) -> set[str]:
    return {
        value
        for value in (alert.hostname, alert.src_ip, alert.src_user)
        if value
    }


def group_into_incidents(
    alerts: list[NormalizedAlert],
) -> list[list[NormalizedAlert]]:
    """Cluster alerts that share an entity and happen close in time.

    Greedy O(n log n) grouping: sort by time, then attach each alert to the
    first existing incident it fits. Good enough for the volumes we see,
    and vastly easier to reason about than a proper clustering algorithm.
    """

    incidents: list[list[NormalizedAlert]] = []

    for alert in sorted(alerts, key=lambda a: a.timestamp):
        alert_entities = _entities(alert)

        for incident in incidents:
            last = incident[-1]
            if alert.timestamp - last.timestamp > CORRELATION_WINDOW:
                continue
            if alert_entities & _entities(last):
                incident.append(alert)
                break
        else:
            incidents.append([alert])

    return incidents


def build_timeline(alerts: list[NormalizedAlert]) -> str:
    """Render a plain-text timeline, one line per event."""
    lines = []
    for alert in sorted(alerts, key=lambda a: a.timestamp):
        stamp = alert.timestamp.strftime("%H:%M:%S")
        lines.append(
            f"{stamp}  {alert.source.value:<10}  {alert.description}"
        )
    return "\n".join(lines)
