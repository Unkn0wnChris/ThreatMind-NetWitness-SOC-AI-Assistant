#Imported dependencies 
import os
import json
import re
from typing import Dict, List, Set

from src.persona import Analyst_Persona
from src.ollama_client import ollama_query

#Load MITRE ATT&CK JSON
MITRE_JSON_PATH = os.path.join(
    os.path.dirname(__file__),
    "enterprise-attack-18.1 latest.json"
)

with open(MITRE_JSON_PATH, "r", encoding="utf-8") as f:
    MITRE_BUNDLE = json.load(f)

#Search index of MITRE ATT&CK techniques through filtering of attack patterns and metadata/IOCs 
def build_technique_index(bundle: dict) -> Dict[str, dict]:
    index = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        external_refs = obj.get("external_references", [])
        for ref in external_refs:
            tid = ref.get("external_id", "")
            if not tid.startswith("T"):
                continue

            index[tid] = {
                "technique_id": tid,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "tactics": [
                    phase.get("phase_name")
                    for phase in obj.get("kill_chain_phases", [])
                ],
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }

    return index


TECHNIQUE_INDEX = build_technique_index(MITRE_BUNDLE)


#Extract MITRE ATT&CK framework from JSON for accurate referencing 
MITRE_VERSION = next(
    (
        obj.get("x_mitre_version")
        for obj in MITRE_BUNDLE.get("objects", [])
        if obj.get("type") == "x-mitre-collection"
    ),
    "unknown"
)

#Parsing of log to extract MITRE ATT&CK tecniques identified by Netwitness SOC analysts 
def extract_declared_techniques(log_text: str) -> Set[str]:
    found = set()

    try:
        data = json.loads(log_text)
    except Exception:
        return found

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k.lower() in {"technique", "techniques"} and isinstance(v, list):
                    for tid in v:
                        if isinstance(tid, str) and tid.startswith("T"):
                            found.add(tid)
                else:
                    walk(v)
        elif isinstance(obj, list):
            for i in obj:
                walk(i)

    walk(data)
    return found


#Creation of compressed text corpus of MITRE ATT&CK techniques 
def build_technique_corpus(index: Dict[str, dict], limit: int = 1090) -> str:
    """
    Builds a compact, deterministic technique corpus
    to avoid token overflow.
    """
    lines = []
    for tid, tech in sorted(index.items()):
        lines.append(
            f"{tid}: {tech['name']} — {tech['description'][:limit]}"
        )
    return "\n".join(lines)

TECHNIQUE_CORPUS = build_technique_corpus(TECHNIQUE_INDEX)

# MITRE attack mapping 
def MITRE_Mapping(log_text: str, persona: str = "L1 SOC Analyst") -> List[dict]:
    results = []
    seen = set()

    #Vendor declared 
    declared_ids = extract_declared_techniques(log_text)

    for tid in declared_ids:
        tech = TECHNIQUE_INDEX.get(tid)
        if not tech:
            continue

        seen.add(tid)
        results.append({
            "technique_id": tid,
            "technique_name": tech["name"],
            "description": tech["description"][:1090],
            "tactic": tech["tactics"],
            "platforms": tech["platforms"],
            "reason": "Explicitly identified by detection engine",
            "confidence": "High",
            "source": "Referenced/Sourced from netwitness",
            "mitre_version": MITRE_VERSION,
        })

    if results:
        return results
    
    
    # AI based(bouded by JSON corpus)
    persona_context = Analyst_Persona.get(persona, "")

    prompt = f"""
{persona_context}

You are mapping a security alert to MITRE ATT&CK techniques.

RULES:
- Use ONLY techniques from the list below
- Do NOT guess
- If no technique is strongly supported, return NONE
- Return at most 3 technique IDs

MITRE ATT&CK TECHNIQUES:
{TECHNIQUE_CORPUS}

ALERT:
{log_text}

Return technique IDs only (one per line).
"""

    try:
        ai_response = ollama_query(prompt)
    except Exception:
        return []

    inferred_ids = set(re.findall(r"T\d{4}(?:\.\d{3})?", ai_response))

    
    # Post validation of JSON 
    for tid in inferred_ids:
        tech = TECHNIQUE_INDEX.get(tid)
        if not tech or tid in seen:
            continue

        results.append({
            "technique_id": tid,
            "technique_name": tech["name"],
            "description": tech["description"][:1090],
            "tactic": tech["tactics"],
            "platforms": tech["platforms"],
            "reason": "AI-selected from MITRE ATT&CK corpus",
            "confidence": "Medium",
            "source": "AI-assisted (JSON-bounded)",
            "mitre_version": MITRE_VERSION,
        })

    return results