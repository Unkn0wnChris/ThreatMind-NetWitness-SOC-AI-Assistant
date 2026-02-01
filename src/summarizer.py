#Imported dependecies 
from src.ollama_client import ollama_query
from src.persona import Analyst_Persona
import json
from typing import Any, Dict, List, Iterable
from datetime import datetime

INCIDENT_OUTPUT_TEMPLATE = """
Incident Summary
Source IP: {source_ip}
Destination IP: {destination_ip}
Source Port: {source_port}
Destination Port: {destination_port}
Time of Attack: {time}
Description: {description}
""".strip()

#Standarizes various timestamp formats into human 
def _normalize_time(value: Any) -> str:
    if value in (None, "", "Unknown"):
        return "Unknown"
    if isinstance(value, str) and any(ch in value for ch in ("-", ":", "T")):
        return value
    try:
        ts = int(value)
        if ts > 1_000_000_000_000:
            ts //= 1000
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)

#
def _get_by_path(obj: Any, path: str) -> Any:
    if not isinstance(obj, dict):
        return None

    # literal key first (e.g., "source.ip")
    if path in obj:
        return obj.get(path)

    # dotted traversal (e.g., {"source": {"ip": ...}})
    cur: Any = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur.get(part)
    return cur


def _safe_get(event: Dict[str, Any], keys: List[str], default: Any = "Unknown") -> Any:
    for key in keys:
        val = _get_by_path(event, key)
        if val not in (None, "", [], {}):
            return val
    return default


def _iter_events(data: Any) -> Iterable[Dict[str, Any]]:
    """
    Supports:
    - pipeline chunks: {"events":[...]}
    - parsed: {"alert":{"events":[...]}}
    - full incident export: {"incidents":[{"alerts":[{"originalAlert":{"events":[...]}}]}]}
    """
    if not isinstance(data, dict):
        return []

    # pipeline chunk shape
    if isinstance(data.get("events"), list):
        return [e for e in data["events"] if isinstance(e, dict)]

    if isinstance(data.get("alert"), dict) and isinstance(data["alert"].get("events"), list):
        return [e for e in data["alert"]["events"] if isinstance(e, dict)]

    # incident export shape
    incidents = data.get("incidents")
    if isinstance(incidents, list):
        out: List[Dict[str, Any]] = []
        for inc in incidents:
            if not isinstance(inc, dict):
                continue
            alerts = inc.get("alerts", [])
            if not isinstance(alerts, list):
                continue
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                events = alert.get("events", [])
                if (not events) and isinstance(alert.get("originalAlert"), dict):
                    events = alert["originalAlert"].get("events", [])
                if isinstance(events, list):
                    out.extend([e for e in events if isinstance(e, dict)])
        return out

    return []


def _extract_key_facts(parsed_log: Any) -> Dict[str, str]:
    facts: Dict[str, str] = {
        "source_ip": "Unknown",
        "destination_ip": "Unknown",
        "source_port": "Unknown",
        "destination_port": "Unknown",
        "time": "Unknown",
        "attack": "Unknown",
    }

    for event in _iter_events(parsed_log):
        facts["source_ip"] = str(_safe_get(event, ["ip_src", "source.ip", "src_ip", "source_ip"], facts["source_ip"]))
        facts["destination_ip"] = str(_safe_get(event, ["ip_dst", "dest.ip", "dst_ip", "dest_ip"], facts["destination_ip"]))
        facts["source_port"] = str(_safe_get(event, ["tcp_srcport", "source.port", "src_port"], facts["source_port"]))
        facts["destination_port"] = str(_safe_get(event, ["tcp_dstport", "dest.port", "dst_port"], facts["destination_port"]))

        raw_time = _safe_get(event, ["time", "event.time", "timestamp"], facts["time"])
        facts["time"] = _normalize_time(raw_time)

        facts["attack"] = str(_safe_get(
            event,
            ["alert", "event.desc", "analysis_desc", "analysis.desc", "msg", "message"],
            facts["attack"]
        ))

    return facts


def summarize_alert(log_text: str, persona: str) -> str:
    persona_context = Analyst_Persona.get(persona, "")

    try:
        parsed_log = json.loads(log_text)
    except Exception:
        parsed_log = {}

    facts = _extract_key_facts(parsed_log)

    # If there's no context, do not invent
    if facts["attack"] == "Unknown" and all(facts[k] == "Unknown" for k in ("source_ip", "destination_ip", "time")):
        description = (
            "Insufficient context in the provided log to produce a reliable summary. "
            "No recognizable source/destination fields or event description were found."
        )
    else:
        description_prompt = f"""
{persona_context}

You are a SOC analyst.

Write ONLY the Description field for an incident summary.

Rules:
- One concise paragraph
- Explain what happened and why it matters
- Do NOT repeat IPs, ports, or timestamps
- Do NOT add headings/bullets
- Do NOT speculate beyond the provided attack context

Attack Context:
{facts["attack"]}
""".strip()

        description = (ollama_query(prompt=description_prompt) or "").strip() or "Unknown"

    return INCIDENT_OUTPUT_TEMPLATE.format(
        source_ip=facts["source_ip"],
        destination_ip=facts["destination_ip"],
        source_port=facts["source_port"],
        destination_port=facts["destination_port"],
        time=facts["time"],
        description=description,
    )

