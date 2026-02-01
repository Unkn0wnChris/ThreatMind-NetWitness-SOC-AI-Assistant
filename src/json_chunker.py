#Imported dependencies
from typing import List, Dict, Iterator, Any
from datetime import datetime
import json
import re

#Timestamp formatter(event level)
def format_event_time(ts):
    """
    Converts epoch timestamps (ms or s) into readable datetime.
    If ts is already a readable string, it will be returned as-is.
    """
    if ts in ("", None):
        return ts

    # If it's already an ISO-ish string, keep it
    if isinstance(ts, str) and any(ch in ts for ch in ("-", "T", ":")):
        return ts

    try:
        ts = int(ts)

        # Convert milliseconds → seconds
        if ts > 1_000_000_000_000:
            ts = ts / 1000

        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts



#Incident level chunking
def chunk_netwitness_incident(
    incident: Dict[str, Any],
    max_events_per_chunk: int = 10
) -> List[Dict[str, Any]]:
    """
    Split a NetWitness incident into multiple chunks by event count.

    IMPORTANT:
    NetWitness incident exports usually store events under:
      alert["originalAlert"]["events"]
    Some parsed formats store under:
      alert["events"]

    This function supports BOTH to prevent empty event chunks (which cause Unknown IP/Port).
    """

    alerts = incident.get("alerts", [])
    all_events: List[Dict[str, Any]] = []

    for alert in alerts:
        # Try both event locations
        events = alert.get("events", [])

        if (not events) and isinstance(alert.get("originalAlert"), dict):
            events = alert["originalAlert"].get("events", [])

        if not isinstance(events, list):
            continue

        for event in events:
            if not isinstance(event, dict):
                continue

            # Remove empty fields dynamically
            cleaned_event = {
                k: v for k, v in event.items()
                if v not in ("", None, [], {})
            }

            # Normalize event timestamp if present
            if "time" in cleaned_event:
                cleaned_event["time"] = format_event_time(cleaned_event["time"])
            elif "event.time" in cleaned_event:
                cleaned_event["event.time"] = format_event_time(cleaned_event["event.time"])

            if cleaned_event:
                all_events.append(cleaned_event)

    # Splitting of chunks based on event count
    chunks: List[Dict[str, Any]] = []

    incident_id = incident.get("id") or incident.get("_id")
    incident_name = incident.get("name")
    priority = incident.get("priority")
    risk_score = incident.get("risk_score") or incident.get("riskScore")

    for i in range(0, len(all_events), max_events_per_chunk):
        chunk_events = all_events[i:i + max_events_per_chunk]
        chunk_num = (i // max_events_per_chunk) + 1

        chunk = {
            "incident_id": incident_id,
            "incident_name": f"{incident_name} (Part {chunk_num})" if len(all_events) > max_events_per_chunk else incident_name,
            "priority": priority,
            "risk_score": risk_score,
            "event_count": len(chunk_events),
            "total_events": len(all_events),
            "events": chunk_events,
        }
        chunks.append(chunk)

    # If still no events, keep a single empty chunk
    if not chunks:
        chunks = [{
            "incident_id": incident_id,
            "incident_name": incident_name,
            "priority": priority,
            "risk_score": risk_score,
            "event_count": 0,
            "total_events": 0,
            "events": [],
        }]

    return chunks



#Incident to text conversion
def chunk_to_text(chunk: Dict[str, Any]) -> str:
    """
    Convert an incident chunk into analyst-style narrative text.
    """
    lines = [
        f"Incident ID: {chunk.get('incident_id')}",
        f"Incident Name: {chunk.get('incident_name')}",
        f"Priority: {chunk.get('priority')}",
        f"Risk Score: {chunk.get('risk_score')}",
        f"Total Events: {chunk.get('event_count')}",
        "Events:"
    ]

    for idx, e in enumerate(chunk.get("events", []), start=1):
        if not isinstance(e, dict):
            continue
        event_parts = [f"{k}: {v}" for k, v in e.items()]
        lines.append(f"{idx}. " + ", ".join(event_parts))

    return "\n".join(lines)


#Text chunking(RAG)
def chunk_text(text: str, chunk_size: int = 300) -> Iterator[str]:
    """
    Chunk text ONLY for embeddings / semantic search.
    Never shown to UI.
    """
    words = text.split()
    for i in range(0, len(words), chunk_size):
        yield " ".join(words[i:i + chunk_size])



# SAFETY: INCIDENT DEDUPLICATION
def deduplicate_incidents(chunks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {}
    for c in chunks:
        seen[c.get("incident_id")] = c
    return list(seen.values())

