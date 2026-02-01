from typing import Any, Dict, List, Optional, Tuple
from src.netwitness_models import AlertSummary, IncidentSummary
from src.netwitness_client import NetWitnessClient

def derive_incident_summary(alerts: List[AlertSummary]) -> Optional[str]:
    '''
    Derive incident severity from related alerts.
    Uses the highest severity among the alerts.
    '''
    order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    highest = None
    score = 0

    for a in alerts:

        sev = (a.severity or "").upper()
        if sev in order and order[sev] > score:
            highest = sev
            score = order[sev]

    return highest

def summarize_alert_item(client: NetWitnessClient, item: Dict[str, Any]) -> AlertSummary:
    src_ips, dst_ips = client.extract_metadata_ips(item)
    return AlertSummary(
        id= str(item.get("id")),
        severity= str(item.get("severity", item.get("priority")) or ""),  
        title= str(item.get("title", "")),
        created= str(item.get("created", "")),
        source= str(item.get("source", "")),
        detail=str(item.get("detail", "")),
        source_ips=src_ips,
        destination_ips=dst_ips
    )

def get_incident_with_related_alerts(
        client: NetWitnessClient, incident_id: str, max_alerts: int = 20
) -> Tuple[IncidentSummary, List[AlertSummary]]:
    incident = client.get_incidents(incident_id)
    src_ips, dst_ips = client.extract_metadata_ips(incident)
    incident_sum = IncidentSummary(
        id=incident_id,
        title=str(incident.get("title", incident.get("name", ""))),
        status=str(incident.get("status", "")),
        priority=str(incident.get("priority", "")),
        created=str(incident.get("created", "")),
        last_updated=str(incident.get("lastUpdated", incident.get("last_updated", ""))),
        source_ips=src_ips,
        destination_ips=dst_ips,
        raw=incident,
    )

    # Fetch related alerts
    alerts_page = client.get_incidents_alerts(
        incident_id,
        page_number=0,
        page_size=5
    )

    items = alerts_page.get("items", []) if isinstance(alerts_page, dict) else []
    alert_summaries = [summarize_alert_item(client, a) for a in items]

    incident_sum.severity = (
        incident.get("severity")
        or derive_incident_summary(alert_summaries)
    )

    return incident_sum, alert_summaries

def get_alerts_brief(client: NetWitnessClient, since: Optional[str] = None, until: Optional[str] = None, max_alerts: int = 20,
) -> Tuple[int, List[AlertSummary]]:
    count = client.get_alert_count(since=since, until=until)
    page = client.get_alerts(since=since, until=until, page_number=0, page_size=5)
    items = page.get("items", []) if isinstance(page, dict) else []
    brief = [summarize_alert_item(client, a) for a in items[:max_alerts]]
    
    return count, brief

def format_incident_and_alerts(inc: IncidentSummary, alerts: List[AlertSummary]) -> str:
    # Consolidating IPs across incident and alerts
    src = set(inc.source_ips or [])
    dst = set(inc.destination_ips or [])
    
    for a in alerts:
        src.update(a.source_ips or [])
        dst.update(a.destination_ips or [])
    
    lines = []
    sev = (inc.severity or "").upper() if hasattr(inc, "severity") else ""
    lines.append(f"Incident {inc.id}: {inc.title} {f'| {sev}' if sev else ''}".strip())


    if inc.status or inc.priority:
        lines.append(f" Status: {inc.status}, Priority: {inc.priority}".strip())
    if src:
        lines.append(f"Source IPs: {', '.join(sorted(src))}")
    if dst:
        lines.append(f"Destination IPs: {', '.join(sorted(dst))}")

    lines.append("")
    lines.append(f"Related Alerts (showing {len(alerts)}):")
    
    for a in alerts:
        lines.append(f"- {a.id} | {str(a.severity).upper()} | {a.created} | {a.title}".strip())
    
    return "\n".join(lines)