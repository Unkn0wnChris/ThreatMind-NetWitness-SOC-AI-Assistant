from typing import Any, Dict
from src.netwitness_client import NetWitnessClient
import re
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def query_sessions_by_ip(client: NetWitnessClient, ip: str, limit: int = 50) -> Dict[str, Any]:
    # This query language depends on your NetWitness metadata schema
    # Keep it simple and flexible to adjust

    netwitness_query = f'select * where ip = "{ip}" limit {int(limit)}'
    
    return client.metadata_query(netwitness_query)

def query_sessions_for_incident_ips(client: NetWitnessClient, incident_obj: Dict[str, Any], limit: int = 50):
    src_ips, dst_ips = client.extract_metadata_ips(incident_obj)
    results = {}
    
    if not IP_RE.match(ip or ""):
        return {"error": f"Invalid IP: {ip}"}

    for ip in sorted(set(src_ips + dst_ips)):
        results[ip] = query_sessions_by_ip(client, ip, limit=limit)
    
    return results
