from typing import Optional
from src.netwitness_client import NetWitnessClient

def fetch_incident_stats_text(client: NetWitnessClient, since: Optional[str] = None, until: Optional[str] = None) -> str:
    try:
        stats = client.get_incident_stats(since=since, until=until, page_number=0, page_size=100)
    except Exception as e:
        return f"Failed to fetch incident stats: {e}"
    
    items = stats.get("items", []) if isinstance(stats, dict) else []
    
    if not items:
        return "No incident stats returned for the selected date range."
    
    # Keep it concise
    '''
    MTTA --> Mean Time to Acknowledge (How long it takes, on average, for an analyst or system to acknowledge an incident after it is created)
    - Why does it matter?
        it measures SOC responsiveness
        high MTTA = alerts sitting unnoticed
    MTTD --> Mean Time to Detect (How long it takes to detect malicious activity after it begins)
    - Why does it matter?
        it measures visibility and detection quality
        long MTTD = blind spots
    MTTR --> Mean Time to Resolve (How long it takes to fully resolve and close an incident after detection.)
    - Why does it matter?
        it measures response effectiveness
        high MTTR = slow containment/remediation

    '''
    lines = ["Incident stats (MTTA/MTTD/MTTR):"]

    for row in items[:10]:
        lines.append(
            f"- {row.get('date')} | MTTA={row.get('mtta')} (n={row.get('mttaCount')}), "
            f"MTTD={row.get('mttd')} (n={row.get('mttdCount')}), "
            f"MTTR={row.get('mttr')} (n={row.get('mttrCount')})"
        )
    return "\n".join(lines) 
   