#Imported dependecies 
import re
from src.ollama_client import ollama_query
from src.persona import Analyst_Persona

def triage_alert(log: str, persona: str) -> str:
    """
    AI-first severity classification with deterministic fallback.
    Returns: Low, Medium, High, or Critical
    """
    baseline = _keyword_baseline_severity(log)
    persona_context = Analyst_Persona[persona]

    prompt = f"""{persona_context}
Determine the incident severity.
Rules:
- Respond with ONE word only
- Allowed values: Low, Medium, High, Critical
- Consider business impact and threat likelihood

Alert: {log}
"""
    try:
        ai_severity = ollama_query(prompt).strip()
        if ai_severity in {"Low", "Medium", "High", "Critical"}:
            return ai_severity
    except Exception:
        pass

    # Fallback if AI fails or returns invalid output
    return baseline

def _keyword_baseline_severity(log: str) -> str:
    """
    Keyword-based severity detection as fallback
    """
    log = log.lower()

    high_patterns = [
        r"ransomware", r"data exfiltration", r"domain admin",
        r"privilege escalation", r"remote code execution"
    ]

    medium_patterns = [
        r"failed login", r"brute force", r"phishing",
        r"suspicious", r"anomalous", r"port scan"
    ]

    for p in high_patterns:
        if re.search(p, log):
            return "High"
    for p in medium_patterns:
        if re.search(p, log):
            return "Medium"

    return "Low"
