#Imported dependencies
import re
import json
from typing import List, Dict
from datetime import datetime

#Loading MITRE ATT&CK json 
with open("enterprise-attack-18.1 latest.json", "r") as f:
    MITRE_MAPPING_DICT = json.load(f)

#Timestamp formatter
def format_timestamp(ts):
    """
    Converts epoch timestamps (ms or s) into readable datetime.
    If ts is already a readable datetime string, keep it.
    """
    if ts is None or ts == "":
        return "Unknown"

    if isinstance(ts, str) and any(ch in ts for ch in ("-", "T", ":")):
        return ts

    try:
        ts = int(ts)
        if ts > 1_000_000_000_000:
            ts = ts / 1000
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

#Loading of JSON log uploaded
def load_json_logs(filepath: str) -> List[Dict]:
    """
    Load NetWitness JSON logs.
    Supports:
    - Single JSON list
    - {"logs": [...]}
    - Newline-delimited JSON (NDJSON)
    """
    with open(filepath, "r") as f:
        try:
            data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "logs" in data:
                return data["logs"]
        except Exception:
            pass

    logs = []
    with open(filepath, "r") as f:
        for line in f:
            try:
                logs.append(json.loads(line))
            except Exception:
                pass
    return logs

#Severity mapper
def severity_label(score: int) -> str:
    if score >= 70:
        return "High"
    elif 40 <= score <= 69:
        return "Medium"
    else:
        return "Low"

#MITRE mapping 
def map_mitre(log_message: str) -> str:
    log_lower = (log_message or "").lower()
    matches = []

    for keyword, value in MITRE_MAPPING_DICT.items():
        if re.search(rf"\b{re.escape(keyword)}\b", log_lower):
            technique_id = value.get("id", "Unknown ID")
            technique_name = value.get("name", "Unknown Technique")
            tactic = value.get("tactic", "Unknown Tactic")
            matches.append(f"{technique_id}: {technique_name} ({tactic})")

    return ", ".join(set(matches)) if matches else "No MITRE ATT&CK technique identified"

#Parsing of JSON log
def parse_netwitness_log(log: Dict) -> Dict:
    """
    Normalize NetWitness log JSON into a consistent internal structure.
    Supports both:
      - metakeys like "source.ip", "dest.ip"
      - event keys like "ip_src", "ip_dst", "tcp_srcport", "tcp_dstport"
    """

    message = (
        log.get("event.desc")
        or log.get("analysis_desc")
        or log.get("alert")
        or log.get("msg")
        or log.get("message")
        or "No description"
    )

    raw_time = log.get("time") or log.get("event.time") or log.get("timestamp")

    parsed = {
        "timestamp": format_timestamp(raw_time),
        "level": log.get("alert.level", "INFO"),
        "message": message,

        # IP / Port (support both styles)
        "source_ip": log.get("source.ip") or log.get("ip_src") or log.get("source_ip"),
        "dest_ip": log.get("dest.ip") or log.get("ip_dst") or log.get("dest_ip"),
        "source_port": log.get("source.port") or log.get("tcp_srcport") or log.get("src_port"),
        "dest_port": log.get("dest.port") or log.get("tcp_dstport") or log.get("dst_port"),

        # Other 
        "username": log.get("username"),
        "service": log.get("service"),
        "device_type": log.get("device.type"),
        "sessionid": log.get("sessionid"),

        # Severity 
        "severity_score": int(log.get("severity", 0)),
    }

    parsed["severity_label"] = severity_label(parsed["severity_score"])
    parsed["mitre"] = map_mitre(parsed["message"])

    return parsed

#Log analyser 
def analyze_logs(logs: List[Dict]) -> List[Dict]:
    analyzed = []
    for log in logs:
        try:
            analyzed.append(parse_netwitness_log(log))
        except Exception:
            continue
    return analyzed

#CLI printout
def main(filepath: str):
    logs = load_json_logs(filepath)
    analyzed_logs = analyze_logs(logs)

    print("Timestamp | Level | Message | Severity | MITRE | Source -> Dest | Ports | User")
    print("-" * 180)

    for log in analyzed_logs:
        print(
            f"{log['timestamp']} | {log['level']} | {log['message']} | "
            f"{log['severity_label']} ({log['severity_score']}) | {log['mitre']} | "
            f"{log['source_ip']} -> {log['dest_ip']} | {log.get('source_port')} -> {log.get('dest_port')} | {log['username']}"
        )


# Example usage
if __name__ == "__main__":
    log_file_path = "netwitness_logs.json"
    main(log_file_path)

