#Imported dependecies 
import json
from pathlib import Path
import datetime
import re
from typing import Any, Dict, List, Tuple

RULE_FILE = Path(__file__).parent / "remediation_rules.json"


# Rule Loading
def load_rules() -> List[dict]:
    with open(RULE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)["rules"]


# Normalization Helpers
def normalize(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (int, float)):
        return value
    return str(value).lower()


def coalesce(*values, default=""):
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return default


# NetWitness / Generic Field Normalization
def normalize_incident_fields(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Accepts many possible incident/log shapes and returns canonical keys:
    - incident_name
    - priority
    - risk_score
    - incident_id
    """
    incident_name = coalesce(
        obj.get("incident_name"),
        obj.get("name"),
        obj.get("incidentName"),
        obj.get("summary"),
        default=""
    )
    priority = coalesce(
        obj.get("priority"),
        obj.get("severity"),
        obj.get("alert_level"),
        default=""
    )
    risk_score = coalesce(
        obj.get("risk_score"),
        obj.get("riskScore"),
        obj.get("risk"),
        default=None
    )
    incident_id = coalesce(
        obj.get("incident_id"),
        obj.get("id"),
        obj.get("_id"),
        default=""
    )

    return {
        "incident_id": incident_id,
        "incident_name": incident_name,
        "priority": priority,
        "risk_score": risk_score,
    }


def extract_events_and_incident(log: Dict[str, Any]) -> List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
    """
    Returns a list of (incident_dict, events_list) pairs, supporting:
    - Chunked format: { incident_name, priority, risk_score, events: [...] }
    - NetWitness export: { incidents: [ { alerts: [ { originalAlert: { events:[...] } } ] } ] }
    - NetWitness-ish: { alerts: [ { originalAlert: { events:[...] } } ] }
    - Fallback: treat as single incident with no events
    """

    def pull_events_from_alert(alert_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Common variants
        if isinstance(alert_obj, dict):
            if "events" in alert_obj and isinstance(alert_obj["events"], list):
                return alert_obj["events"]

            original = alert_obj.get("originalAlert")
            if isinstance(original, dict) and isinstance(original.get("events"), list):
                return original["events"]

        return []

    results: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = []

    # Case A: already chunked / normalized
    if isinstance(log.get("events"), list):
        inc = normalize_incident_fields(log)
        results.append((inc, log["events"]))
        return results

    # Case B: top-level alerts
    if isinstance(log.get("alerts"), list):
        inc = normalize_incident_fields(log)
        events: List[Dict[str, Any]] = []
        for a in log["alerts"]:
            events.extend(pull_events_from_alert(a))
        results.append((inc, events))
        return results

    # Case C: incidents array
    if isinstance(log.get("incidents"), list):
        for inc_obj in log["incidents"]:
            if not isinstance(inc_obj, dict):
                continue
            inc = normalize_incident_fields(inc_obj)
            events: List[Dict[str, Any]] = []

            if isinstance(inc_obj.get("events"), list):
                events = inc_obj["events"]
            elif isinstance(inc_obj.get("alerts"), list):
                for a in inc_obj["alerts"]:
                    events.extend(pull_events_from_alert(a))

            results.append((inc, events))

        return results

    # Fallback: unknown shape
    inc = normalize_incident_fields(log)
    results.append((inc, []))
    return results



# Context Extraction
def extract_dynamic_fields(incident: dict) -> dict:
    context = {}
    name = normalize(incident.get("incident_name", ""))

    # Extract username if present
    match = re.search(r"by (\w+)", name)
    if match:
        context["user"] = match.group(1)

    # Infer authentication action
    if "failed" in name and "login" in name:
        context["action"] = "failed authentication"
    elif "login success" in name or "successful login" in name:
        context["action"] = "successful authentication"

    return context


def semantic_time(ts: int) -> str:
    dt = datetime.datetime.utcfromtimestamp(ts / 1000)
    hour = dt.hour
    weekday = dt.weekday()

    if weekday >= 5:
        return "weekend"
    if hour < 8 or hour > 18:
        return "after hours"
    return "business hours"


# Event Construction
EVENT_FIELD_ALIASES = {
    # common NetWitness-ish keys → canonical keys
    "ip_src": ["ip_src", "source.ip", "src_ip", "srcip"],
    "ip_dst": ["ip_dst", "dest.ip", "dst_ip", "dstip"],
    "domain_dst": ["domain_dst", "domain", "host", "hostname", "alias_host"],
    "host": ["host", "hostname", "device_host", "dest_host", "src_host"],
    "user": ["user", "username", "account", "acct", "subject_user"],
}

def _get_first_present(event: Dict[str, Any], keys: List[str]):
    for k in keys:
        if k in event and event[k] not in (None, "", [], {}):
            return event[k]
    return None

def build_effective_event(event: dict, incident: dict) -> dict:
    combined: Dict[str, Any] = {}

    # Incident-level fields (canonical)
    combined["incident_name"] = normalize(incident.get("incident_name"))
    combined["priority"] = normalize(incident.get("priority"))
    combined["risk_score"] = incident.get("risk_score")

    # Event-level fields (raw)
    if isinstance(event, dict):
        for k, v in event.items():
            combined[k] = normalize(v)

        # Add canonical event aliases
        for canon, keys in EVENT_FIELD_ALIASES.items():
            v = _get_first_present(event, keys)
            if v is not None:
                combined[canon] = normalize(v)

    # Dynamic enrichment
    combined.update(extract_dynamic_fields(incident))

    # Semantic time (only if epoch-like)
    if "time" in event:
        try:
            combined["time"] = semantic_time(int(event["time"]))
        except Exception:
            pass

    return combined



# Condition Matching
def _value_matches_expected(value: Any, expected_values: List[str], field: str) -> bool:
    # Numeric comparison
    if field == "risk_score":
        try:
            return int(value) >= int(expected_values[0])
        except Exception:
            return False

    value_str = str(value)

    # Regex / substring matching (expected_values are treated as regex patterns)
    for ev in expected_values:
        try:
            if re.search(ev, value_str):
                return True
        except re.error:
            # If rule author wrote a bad regex, fall back to substring match
            if str(ev) in value_str:
                return True

    return False


def match_conditions_all(effective_event: dict, conditions: dict) -> bool:
    """All listed fields must match."""
    for field, expected_values in conditions.items():
        if field not in effective_event:
            return False
        if not _value_matches_expected(effective_event[field], expected_values, field):
            return False
    return True


def match_conditions_any(effective_event: dict, conditions: dict) -> bool:
    """At least one field must match."""
    for field, expected_values in conditions.items():
        if field not in effective_event:
            continue
        if _value_matches_expected(effective_event[field], expected_values, field):
            return True
    return False


# Persona Normalization
PERSONA_ALIASES = {
    "l1": "L1 SOC Analyst",
    "l2": "L2 SOC Analyst",
    "l3": "L3 SOC Analyst / IR",
    "ir": "L3 SOC Analyst / IR",
    "cti": "Cyber Threat Intelligence Analyst (CTI)",
}


# Public helper (for placeholder filling)
def get_first_effective_event(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Returns a canonical "effective event" for placeholder population.
    """
    pairs = extract_events_and_incident(log)
    if not pairs:
        return {}
    inc, events = pairs[0]
    first_event = events[0] if events else {}
    return build_effective_event(first_event, inc)



# Rule Engine
def run_rule_engine(log: dict, persona: str) -> list:
    rules = load_rules()
    hits = []
    highest_severity = 0

    # Normalize persona
    persona_key = PERSONA_ALIASES.get((persona or "").lower(), persona)

    incident_event_pairs = extract_events_and_incident(log)

    for (incident, events) in incident_event_pairs:
        if not isinstance(events, list):
            continue

        # If there are no events, we can still match on incident_name / priority / risk_score
        if not events:
            events = [{}]

        for rule in rules:
            severity = rule.get("severity", 0)
            persona_actions = rule.get("actions", {}).get(persona_key)

            if not persona_actions:
                continue

            for event in events:
                effective_event = build_effective_event(event, incident)

                conditions_all = rule.get("conditions_all")
                conditions_any = rule.get("conditions_any")

                matched = False

                if conditions_all:
                    matched = match_conditions_all(effective_event, conditions_all)
                elif conditions_any:
                    matched = match_conditions_any(effective_event, conditions_any)

                if not matched:
                    continue

                if severity < highest_severity:
                    break

                highest_severity = max(highest_severity, severity)

                hits.append({
                    "rule_id": rule["id"],
                    "severity": severity,
                    "description": rule.get("description", ""),
                    "actions": persona_actions,
                    "incident_id": incident.get("incident_id", ""),
                    "incident_name": incident.get("incident_name", ""),
                })

                break

    # Sort strongest first (helps UI consistency)
    hits.sort(key=lambda x: x.get("severity", 0), reverse=True)
    return hits

