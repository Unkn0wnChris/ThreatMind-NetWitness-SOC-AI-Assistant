# ============================================================
# PATH & STANDARD IMPORTS
# ============================================================
import sys
import os
import json
import re
import tempfile
from datetime import datetime
import streamlit as st
import requests
from urllib.parse import urlparse


# Ensure project root is on sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ============================================================
# SRC IMPORTS
# ============================================================
from src.ollama_client import ollama_query, check_ollama_connection
from src.persona import Analyst_Persona
from src.summarizer import summarize_alert
from src.triage import triage_alert
from src.mitre_mapper import MITRE_Mapping

# ============================================================
# NETWITNESS IMPORTS
# ============================================================
from src.netwitness_client import NetWitnessConfig, NetWitnessClient
from src.netwitness_queries import(
    get_incident_with_related_alerts,
    get_alerts_brief,
    format_incident_and_alerts,
)
from src.netwitness_automation import fetch_incident_stats_text
from src.netwitness_metadata import query_sessions_by_ip


# Optional MITRE context analysis (if present)
try:
    from src.mitre_mapper import analyze_mitre_attack_context
except Exception:
    analyze_mitre_attack_context = None

from src.remediation import suggest_remediation

# Optional NetWitness pipeline (only if available)
try:
    from src.pipeline import build_retriever_from_netwitness
    from src.correlation_engine import CorrelationEngine
    PIPELINE_AVAILABLE = True
except Exception:
    PIPELINE_AVAILABLE = False


# ============================================================
# SAFE HELPER: ENSURE JSON STRING
# ============================================================

def ensure_json_str(x) -> str:
    """
    Pipeline chunks are sometimes dicts. Summarizer expects a JSON string.
    """
    try:
        return x if isinstance(x, str) else json.dumps(x)
    except Exception:
        return str(x)


# ============================================================
# Prompt Parsing Helper (NetWitness)
# ============================================================
INC_RE = re.compile(r"\bINC-\d+\b",re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def extract_incident_id(prompt: str) -> str:
    m = INC_RE.search(prompt or "")
    return m.group(0).upper() if m else ""

def extract_ip(prompt: str) -> str:
    m = IP_RE.search(prompt or "")
    return m.group(0) if m else ""

def prompt_needs_netwitness(prompt: str) -> bool:
    p = (prompt or "").lower()
    return any(k in p for k in ["incident", "inc-", "alert", "alerts", "mtta", "mttd", "mttr", "stats", "session", "metadata" ])

# ============================================================
# CLOUDSHARE NETWITNESS CONNECTION - UPDATED WITH CORRECT PARAMETERS
# ============================================================
def clean_domain(host: str) -> str:
    """Clean domain by removing protocol and port"""
    host = host.strip().rstrip("/")
    
    # Remove https:// or http:// prefix
    if host.startswith("http://"):
        host = host[7:]
    elif host.startswith("https://"):
        host = host[8:]
    
    # Remove port if present
    if ":" in host:
        host = host.split(":")[0]
    
    return host

def get_nw_client() -> NetWitnessClient:
    """Get or create NetWitness client with your CloudShare configuration"""
    if "nw_client" not in st.session_state:
        # YOUR SPECIFIC CLOUDSHARE CONFIGURATION
        # Based on your NetWitnessConfig class parameters
        domain = clean_domain(st.session_state.get("nw_host", "uvo1gp037tg5ufq0prf.vm.cld.sr"))
        username = st.session_state.get("nw_username", "admin")
        respond_pw = st.session_state.get("nw_respond_password", "")
        metadata_pw = st.session_state.get("nw_metadata_password", "")
        
        config = NetWitnessConfig(
            domain=domain,

            respond_username=username,
            respond_password=respond_pw,

            metadata_username=username,
            metadata_password=metadata_pw,

            verify_ssl=False,
            timeout_secs=30
        )
        st.session_state.nw_client = NetWitnessClient(config)
    return st.session_state.nw_client

def build_netwitness_context(prompt: str) -> str:
    """
    Fetch data from CloudShare NetWitness based on prompt.
    Routes:
      - INC-#### -> incident + related alerts (formatted)
      - stats/mtta/mttd/mttr -> incident stats summary text
      - alert/alerts -> alert count + brief list
      - IP address -> session/metadata lookup (query_sessions_by_ip)
    """
    try:
        client = get_nw_client()
        p = (prompt or "").lower()

        # 1) Incident flow (INC-###)
        inc_id = extract_incident_id(prompt)
        if inc_id:
            try:
                # IMPORTANT: use the wrapper that returns your models
                inc_summary, alert_summaries = get_incident_with_related_alerts(client, inc_id, max_alerts=20)
                return format_incident_and_alerts(inc_summary, alert_summaries)
            except Exception as e:
                msg = f"Failed to fetch incident {inc_id}:\n{type(e).__name__}: {e}"
                if "404" in str(e):
                    msg += "\n⚠️ Incident not found. Try 'recent alerts' or 'incident stats' to see available IDs."
                elif "401" in str(e) or "403" in str(e):
                    msg += "\n⚠️ Auth error. Verify Respond credentials and token acquisition."
                elif "500" in str(e):
                    msg += "\n⚠️ Server error from Respond API (500). In CloudShare this sometimes happens when:"
                    msg += "\n  • the INC-ID does not exist (API returns 500 instead of 404), or"
                    msg += "\n  • the proxy/WAF dislikes explicit :443 in the URL, or"
                    msg += "\n  • the incident record has a backend error."

                    # Fallback: try listing recent incidents so the user can pick a valid ID
                    try:
                        recent = client.list_incidents(page_number=0, page_size=10)
                        # Extract any INC-#### patterns from the payload robustly
                        recent_text = json.dumps(recent)[:5000]
                        ids = sorted(set(re.findall(r"INC-\\d+", recent_text)))
                        if ids:
                            msg += "\n\n✅ Here are some incident IDs available in your environment:"
                            msg += "\n" + ", ".join(ids[:10])
                            msg += "\n\nTry: Show " + ids[0]
                        else:
                            msg += "\n\nℹ️ Could not extract incident IDs from the list response."
                    except Exception as list_err:
                        msg += f"\n\nℹ️ Also failed to list incidents: {type(list_err).__name__}: {list_err}"
                return msg

        # 2) Stats flow
        if any(k in p for k in ["stats", "mtta", "mttd", "mttr"]):
            try:
                return fetch_incident_stats_text(client)
            except Exception as e:
                return f"Failed to fetch incident stats:\n{type(e).__name__}: {e}"

        # 3) Alerts flow (count + brief list)
        if "alert" in p or "alerts" in p:
            try:
                count, alerts = get_alerts_brief(client, max_alerts=20)
                lines = [f"Alert count: {count}", "Recent alerts (concise):"]
                for a in alerts:
                    sev = (a.severity or "").upper()
                    lines.append(f"- {a.id} | {sev} | {a.created} | {a.title}".strip())
                return "\n".join(lines)
            except Exception as e:
                return f"Failed to fetch alerts:\n{type(e).__name__}: {e}"

        # 4) Sessions/metadata by IP
        ip = extract_ip(prompt)
        if ip:
            try:
                sessions = query_sessions_by_ip(client, ip, limit=20)
                # Trim so we don't blow the LLM context
                s = json.dumps(sessions, default=str, indent=2)
                if len(s) > 4000:
                    s = s[:4000] + "\n... (truncated)"
                return f"Sessions for IP {ip}:\n{s}"
            except Exception as e:
                return f"Failed to query sessions for IP {ip}:\n{type(e).__name__}: {e}"

        return "No specific NetWitness data found for this query. Try: 'INC-91', 'incident stats', 'recent alerts', or 'sessions for 1.2.3.4'."

    except Exception as e:
        return f"Error connecting to NetWitness:\n{type(e).__name__}: {e}"


# ============================================================
# TEST CLOUDSHARE CONNECTION FUNCTION
# ============================================================
def test_cloudshare_connection(host: str, username: str, respond_password: str, metadata_password) -> dict:
    """
    Test connection to your specific CloudShare NetWitness instance
    """
    results = {
        "connected": False,
        "message": "",
        "details": {},
        "error": None
    }
    
    try:
        # Clean the domain
        domain = clean_domain(host)
        
        # Create config with correct parameters
        test_config = NetWitnessConfig(
            domain=domain,

            respond_username=username,
            respond_password=respond_password,

            metadata_username=username,
            metadata_password=metadata_password,

            verify_ssl=False,
            timeout_secs=15
        )
        
        test_client = NetWitnessClient(test_config)
        
        # Try authentication to test connection
        token = test_client.authenticate()
        
        results["connected"] = True
        results["message"] = f"✅ Successfully connected to CloudShare NetWitness at {domain}"
        results["details"] = {
            "domain": domain,
            "authenticated": True if token else False,
            "api_version": "CloudShare NetWitness"
        }
        
        # Try a simple query to verify API access
        try:
            stats = test_client.get_incident_stats()
            results["details"]["incident_count"] = stats.get('totalItems', 0) or len(stats.get('items', []))
        except Exception as api_error:
            results["details"]["api_test"] = f"API query failed: {str(api_error)[:100]}"
        
    except Exception as e:
        results["connected"] = False
        results["message"] = f"❌ Failed to connect to CloudShare NetWitness"
        results["error"] = str(e)
        results["details"] = {
            "domain": clean_domain(host),
            "suggestions": [
                "Verify the domain is correct: uvo1gp037tg5ufq0prf.vm.cld.sr",
                "Check if password is correct (try 'Password123!' or 'netwitness')",
                "Ensure the CloudShare instance is running",
                "Check network connectivity"
            ]
        }
    
    return results

# ============================================================
# STREAMLIT CONFIG
# ============================================================
st.set_page_config(page_title="SOCGPT – AI-Powered SOC Assistant", layout="wide")
st.title("🔎 SOC AI-Powered Assistant (CloudShare NetWitness)")

# ============================================================
# SESSION STATE DEFAULTS
# ============================================================
defaults = {
    # Single-log cache (preserved)
    "analysis_cache": {},

    # Pipeline state
    "logs": [],
    "log_retriever": None,
    "correlation_engine": None,
    "incident_timeline": None,
    "log_analysis_cache": {},

    # Chat state
    "chat_history": [],

    # UI modes
    "analysis_mode": "Manual",
    "remediation_mode": "ai-based",

    # Health check latch
    "ollama_checked": False,

    # allows resetting file uploader
    "uploader_key": 0,
    
    # NetWitness configuration (YOUR CLOUDSHARE)
    "nw_host": "uvo1gp037tg5ufq0prf.vm.cld.sr",
    "nw_username": "admin",

    # ✅ store 2 passwords
    "nw_respond_password": "",
    "nw_metadata_password": "",

    "nw_configured": False,
    "nw_connection_status": None,
}
for k, v in defaults.items():
    st.session_state.setdefault(k, v)

# ============================================================
# OLLAMA HEALTH CHECK
# ============================================================
if not st.session_state.ollama_checked:
    st.session_state.ollama_checked = True
    if not check_ollama_connection():
        st.error("❌ Ollama is not running")
        st.stop()

# ============================================================
# SIDEBAR – SETTINGS & NETWITNESS CONFIG
# ============================================================
with st.sidebar:
    st.header("⚙️ Settings")
    Persona = st.selectbox("Analyst Persona", list(Analyst_Persona.keys()))
    st.info(Analyst_Persona[Persona])

    st.session_state.remediation_mode = st.radio(
        "Remediation Mode", ["AI-based", "Rule-based", "Hybrid"]
    ).lower()

    # YOUR CLOUDSHARE NETWITNESS CONFIGURATION
    st.divider()
    st.header("🌐 CloudShare NetWitness Configuration")
    
    st.success("✅ **Your CloudShare Instance Configured**")
    st.markdown("""
    **Your Instance Details:**
    - **Domain:** `uvo1gp037tg5ufq0prf.vm.cld.sr`
    - **Respond API (Incidents/Alerts):** Port 443
    - **Metadata API:** Port 12346 (fallback: 50103)
    - **Default Passwords:** `Password123!` (Respond) or `netwitness` (Metadata)
    """)
    
    # Configuration inputs with your defaults pre-filled
    nw_host = st.text_input(
        "CloudShare Domain (without https://)",
        value=clean_domain(st.session_state.get("nw_host", "uvo1gp037tg5ufq0prf.vm.cld.sr")),
        help="Enter just the domain, e.g., uvo1gp037tg5ufq0prf.vm.cld.sr"
    )
    
    nw_username = st.text_input(
        "Username",
        value=st.session_state.get("nw_username", "admin"),
        help="Default: admin"
    )
    
    nw_respond_password = st.text_input(
        "Respond Password (Incidents/Alerts - Port 443)",
        type="password",
        value=st.session_state.get("nw_respond_password", ""),
        placeholder="Default: Password123!",
        help="Used for /rest/api (incidents/alerts). Default is usually Password123!"
    )

    nw_metadata_password = st.text_input(
        "Metadata Password (Sessions/SDK - Port 12346/50103)",
        type="password",
        value=st.session_state.get("nw_metadata_password", ""),
        placeholder="Default: netwitness",
        help="Used for /sdk metadata queries. Default is usually netwitness"
    )

    
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("💾 Save", use_container_width=True):
            st.session_state.nw_host = nw_host.strip()
            st.session_state.nw_username = nw_username.strip()
            st.session_state.nw_respond_password = nw_respond_password.strip()
            st.session_state.nw_metadata_password = nw_metadata_password.strip()
            st.session_state.nw_configured = True
            
            # Clear existing client to force reconnection
            if "nw_client" in st.session_state:
                del st.session_state["nw_client"]
            
            st.success("CloudShare configuration saved!")
            st.rerun()
    
    with col2:
        if st.button("🔗 Test", use_container_width=True):
            if not nw_host or not nw_username or not nw_respond_password or not nw_metadata_password:
                st.error("Please fill: host, username, Respond password, Metadata password")

            else:
                with st.spinner("Testing CloudShare connection..."):
                    test_results = test_cloudshare_connection(
                        nw_host.strip(),
                        nw_username.strip(),
                        nw_respond_password.strip(),
                        nw_metadata_password.strip()
                    )
                        
                    st.session_state.nw_connection_status = test_results
                    
                    if test_results["connected"]:
                        st.success(test_results["message"])
                        with st.expander("Connection Details", expanded=True):
                            st.json(test_results["details"])
                    else:
                        st.error(test_results["message"])
                        with st.expander("Error Details", expanded=True):
                            st.write(test_results.get("error", "Unknown error"))
                            if test_results.get("details", {}).get("suggestions"):
                                st.write("**Suggestions:**")
                                for suggestion in test_results["details"]["suggestions"]:
                                    st.write(f"- {suggestion}")
    
    with col3:
        if st.button("🔄 Reset", use_container_width=True):
            st.session_state.nw_client = None
            st.session_state.nw_connection_status = None
            st.success("Connection reset")
            st.rerun()
    
    # Show connection status
    if st.session_state.get("nw_connection_status") is not None:
        status = st.session_state.nw_connection_status
        if status.get("connected"):
            st.success(f"✅ Connected to: {status.get('details', {}).get('domain', 'CloudShare')}")
        else:
            st.error("❌ Not connected to CloudShare")
    
    # Quick incident test
    st.divider()
    st.subheader("Quick Incident Test")
    test_incident = st.text_input("Test Incident ID", placeholder="INC-97")
    if st.button("Test Fetch Incident", use_container_width=True) and test_incident:
        if not st.session_state.get("nw_configured"):
            st.error("Please save configuration first")
        else:
            with st.spinner(f"Fetching {test_incident}..."):
                try:
                    context = build_netwitness_context(f"show {test_incident}")
                    if "Failed" in context or "error" in context.lower():
                        st.error(f"Failed: {context}")
                    else:
                        st.success(f"✅ Fetched {test_incident}")
                        with st.expander("Preview", expanded=True):
                            st.text_area("Incident Data", context[:1000] + ("..." if len(context) > 1000 else ""), height=150)
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    
    st.divider()
    
    if st.button("🔌 Check Ollama Connection"):
        if check_ollama_connection():
            st.success("Ollama connected")
        else:
            st.error("Ollama not reachable")

    if st.button("Clear Chat"):
        if "nw_client" in st.session_state:
            del st.session_state["nw_client"]
        st.session_state.chat_history = []
        st.session_state.analysis_cache = {}
        st.session_state.logs = []
        st.session_state.log_retriever = None
        st.session_state.correlation_engine = None
        st.session_state.incident_timeline = None
        st.session_state.log_analysis_cache = {}
        st.session_state.uploader_key += 1
        st.success("Cleared chat + reset analysis + cleared pipeline.")
        st.rerun()

    if st.button("Reset Pipeline (Clear Loaded Chunks)"):
        st.session_state.logs = []
        st.session_state.log_retriever = None
        st.session_state.correlation_engine = None
        st.session_state.incident_timeline = None
        st.session_state.log_analysis_cache = {}
        st.success("Pipeline cleared")
        st.rerun()

# ============================================================
# ONE UPLOADER (Unified)
# ============================================================
st.markdown("## 📥 Upload / Paste Alert or Log")

uploaded_file = st.file_uploader(
    "Upload JSON/TXT log. NetWitness incident JSON will auto-run pipeline if available.",
    type=["json", "txt"],
    key=f"unified_upload_{st.session_state.uploader_key}"
)

log_input = ""
parsed_json = None

if uploaded_file is not None:
    try:
        log_input = uploaded_file.read().decode("utf-8")
    except Exception:
        st.error("Failed to read uploaded file.")
        st.stop()

    try:
        parsed_json = json.loads(log_input)
    except Exception:
        parsed_json = None
else:
    log_input = st.text_area("Or paste your log here", height=220)

if not (log_input or "").strip():
    st.info("Upload or paste a log to run log analysis. (Chat is still available below.)")

has_log = bool ((log_input or "").strip())


def looks_like_netwitness_incident(obj: dict) -> bool:
    if not isinstance(obj, dict):
        return False
    return any(k in obj for k in ("incidents", "alerts", "originalAlert", "events"))

# ============================================================
# AUTO-ROUTE TO PIPELINE OR SINGLE-LOG
# ============================================================
use_pipeline = False
is_netwitness_like = parsed_json is not None and looks_like_netwitness_incident(parsed_json)

if is_netwitness_like and PIPELINE_AVAILABLE:
    use_pipeline = True
elif is_netwitness_like and not PIPELINE_AVAILABLE:
    st.info("NetWitness pipeline modules not available; falling back to single-log workflow.")

# ============================================================
# RUN PIPELINE
# ============================================================
if use_pipeline:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp.write(log_input.encode("utf-8"))
        temp_path = tmp.name

    retriever = build_retriever_from_netwitness(temp_path, chunked=True, max_events_per_chunk=3)
    st.session_state.log_retriever = retriever
    st.session_state.logs = retriever.logs
    st.session_state.correlation_engine = CorrelationEngine(retriever.logs)
    st.success(f"Loaded {len(retriever.logs)} incident chunks")

# ============================================================
# MAIN UI: PIPELINE MODE
# ============================================================
if st.session_state.logs:
    st.subheader("🧠 AI Log Analysis (Pipeline)")

    for idx, log in enumerate(st.session_state.logs):
        cache_key = f"log_{idx}"

        with st.expander(f"Log {idx + 1}", expanded=False):
            analyzed = False
            log_str = ensure_json_str(log)

            # AUTO mode
            if st.session_state.analysis_mode == "Auto":
                if cache_key not in st.session_state.log_analysis_cache:
                    st.session_state.log_analysis_cache[cache_key] = {
                        "summary": summarize_alert(log_str, Persona),
                        "severity": triage_alert(log_str, Persona),
                        "mitre": MITRE_Mapping(log_str),
                        "remediation": suggest_remediation(
                            log_str, persona=Persona, mode=st.session_state.remediation_mode
                        ),
                    }
                result = st.session_state.log_analysis_cache[cache_key]
                analyzed = True

            # MANUAL mode
            else:
                if st.button("🔍 Analyze Log", key=f"analyze_{idx}", use_container_width=True):
                    if cache_key not in st.session_state.log_analysis_cache:
                        st.session_state.log_analysis_cache[cache_key] = {
                            "summary": summarize_alert(log_str, Persona),
                            "severity": triage_alert(log_str, Persona),
                            "mitre": MITRE_Mapping(log_str),
                            "remediation": suggest_remediation(
                                log_str, persona=Persona, mode=st.session_state.remediation_mode
                            ),
                        }
                    result = st.session_state.log_analysis_cache[cache_key]
                    analyzed = True

            if analyzed:
                with st.container(border=True):
                    col1, col2 = st.columns([3, 1])

                    with col1:
                        st.markdown("### Summary")
                        st.write(result["summary"])

                    with col2:
                        st.markdown("### Severity")
                        st.markdown(result["severity"])

                    tab1, tab2, tab3 = st.tabs(["MITRE ATT&CK", "Remediation", "Raw Log"])

                    with tab1:
                        if not result["mitre"]:
                            st.info("No MITRE ATT&CK techniques detected.")
                        else:
                            for t in result["mitre"]:
                                st.markdown(f"### {t.get('technique_id','—')} — {t.get('technique_name','—')}")
                                st.markdown(f"- **Tactic:** {', '.join(t.get('tactic', [])) if t.get('tactic') else '—'}")
                                st.markdown(f"- **Description:** {t.get('description','—')}")
                                st.markdown(f"- **Reason:** {t.get('reason','—')}")
                                st.markdown(f"- **Confidence:** {t.get('confidence','—')}")
                                st.markdown(f"- **Source:** {t.get('source','—')}")
                                st.markdown("---")

                        if analyze_mitre_attack_context:
                            st.markdown("#### MITRE Context Analysis")
                            st.write(analyze_mitre_attack_context(log_str, result["mitre"]))

                    with tab2:
                        st.markdown("### Recommended Actions")
                        st.write(result["remediation"])

                    with tab3:
                        st.code(log_str, language="json")

# ============================================================
# SINGLE LOG MODE (ONLY IF WE HAVE A LOG)
# ============================================================
elif has_log:
    st.subheader("🧾 Single Log Analysis")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("## 🤖 Incident Summary")
        summary = st.session_state.analysis_cache.get((log_input, "summary"))
        if summary is None:
            summary = summarize_alert(log_input, persona=Persona)
            st.session_state.analysis_cache[(log_input, "summary")] = summary
        st.markdown(summary)

    with col1:
        st.markdown("## 🚨 Severity Level")
        severity = st.session_state.analysis_cache.get((log_input, "severity"))
        if severity is None:
            severity = triage_alert(log_input, persona=Persona)
            st.session_state.analysis_cache[(log_input, "severity")] = severity
        st.markdown(f"### **{severity}**")

    with col2:
        st.markdown("## 🎯 MITRE ATT&CK Mapping")
        mitre_hits = st.session_state.analysis_cache.get((log_input, "mitre"))
        if mitre_hits is None:
            try:
                mitre_hits = MITRE_Mapping(log_input, persona=Persona)
            except Exception as e:
                st.error(f"MITRE Mapping failed: {e}")
                mitre_hits = []
            st.session_state.analysis_cache[(log_input, "mitre")] = mitre_hits

        if mitre_hits:
            for m in mitre_hits:
                st.markdown(f"""
### {m.get('technique_id','—')} — {m.get('technique_name','—')}
- **Tactic:** {', '.join(m.get('tactic', [])) if m.get('tactic') else '—'}
- **Description:** {m.get('description','—')}
- **Reason:** {m.get('reason','—')}
- **Confidence:** {m.get('confidence','—')}
- **Source:** {m.get('source','—')}
""")
        else:
            st.info("No MITRE techniques detected.")

    st.markdown("## 🛠️ Recommended Remediation")
    remediation_value = st.session_state.analysis_cache.get((log_input, "remediation"))
    if remediation_value is None:
        remediation_value = suggest_remediation(
            log_input, persona=Persona, mitre_hits=mitre_hits, mode=st.session_state.remediation_mode
        )
        st.session_state.analysis_cache[(log_input, "remediation")] = remediation_value
    st.markdown(remediation_value)

# ============================================================
# NO LOG MODE (WHEN NO LOG IS PROVIDED)
# ============================================================
else:
    st.info("📝 **Welcome!** Please upload a log file or paste log text above to see AI-powered analysis.")
    st.markdown("""
    ### What you can do:
    1. **Upload a log file** (JSON or TXT format)
    2. **Paste log text** in the text area above
    3. **Use the chatbot below** to fetch real incidents from CloudShare
    4. **Configure CloudShare NetWitness** in sidebar (pre-configured)
    
    ### Example logs to try:
    - NetWitness incident JSON exports
    - Security alert logs
    - Firewall logs
    - IDS/IPS alerts
    """)

# ============================================================
# CHAT SECTION WITH YOUR CLOUDSHARE NETWITNESS INTEGRATION
# ============================================================
st.markdown("---")
st.header("💬 Chat with SOCGPT - Connected to Your CloudShare NetWitness")

# Show CloudShare status prominently
if st.session_state.get("nw_configured") and st.session_state.get("nw_connection_status") and st.session_state.nw_connection_status.get("connected"):
    st.success(f"✅ **Connected to CloudShare:** {st.session_state.nw_host}")
    st.markdown("""
    **Ask about real incidents in your CloudShare instance:**
    - "Show INC-97" - Fetch specific incident
    - "Recent alerts" - Get latest alerts
    - "Incident stats" - View statistics
    - "Sessions for 192.168.1.1" - Search by IP
    - "Compare INC-10 and INC-20" - Compare incidents
    """)
elif st.session_state.get("nw_configured"):
    st.warning("⚠️ **CloudShare Configured but Not Connected**")
    st.markdown("Click 'Test' in sidebar to establish connection")
else:
    st.info("🔧 **Configure CloudShare in sidebar** to fetch real incident data")

# Show chat history
for msg in st.session_state.chat_history:
    if msg["role"] == "user":
        st.markdown(f"**You:** {msg['content']}")
    else:
        st.markdown(f"**SOCGPT:** {msg['content']}")

# Chat input
user_prompt = st.text_input("Type your query (e.g., 'Show me INC-97 from CloudShare')...")

if st.button("Send", use_container_width=True) and user_prompt.strip():
    prompt = user_prompt.strip()

    # Add to chat history
    st.session_state.chat_history.append({"role": "user", "content": prompt})
    
    # Check if we need NetWitness data
    use_nw = prompt_needs_netwitness(prompt)
    context = ""
    
    if use_nw:
        if not st.session_state.get("nw_configured"):
            answer = """
⚠️ **CloudShare NetWitness Not Configured**

Please configure your CloudShare NetWitness connection in the sidebar:
1. Domain: `uvo1gp037tg5ufq0prf.vm.cld.sr` (pre-filled)
2. Username: `admin` (pre-filled)
3. Enter your password (try 'Password123!' or 'netwitness')
4. Click "Save" then "Test"
"""
        else:
            with st.spinner("🔍 Fetching real data from your CloudShare NetWitness..."):
                try:
                    context = build_netwitness_context(prompt)
                    
                    if context and "Failed" not in context and "error" not in context.lower():
                        # Successfully fetched real data
                        final_prompt = f"""
You are a SOC analyst AI analyzing REAL-TIME data from CloudShare NetWitness.

CLOUDSHARE NETWITNESS DATA (REAL INCIDENTS/ALERTS):
{context}

USER QUESTION:
{prompt}

INSTRUCTIONS:
1. Analyze the REAL CloudShare NetWitness data above
2. Reference specific incident/alert IDs mentioned in the data
3. Provide actionable security insights
4. Suggest investigation steps based on real data
5. Estimate severity levels
6. Recommend remediation actions

ANSWER BASED ON REAL CLOUDSHARE DATA:
"""
                        answer = ollama_query(final_prompt)
                        answer = f"**🌐 REAL DATA FROM YOUR CLOUDSHARE NETWITNESS**\n\n{answer}"
                    
                    elif "Failed" in context or "error" in context.lower():
                        # Connection/query failed
                        answer = f"""
⚠️ **CloudShare Query Failed**

{context}

**Troubleshooting:**
1. Check if CloudShare instance is running
2. Verify credentials in sidebar
3. Try 'Password123!' or 'netwitness' as password
4. Test connection in sidebar
"""
                    else:
                        # No specific data found
                        final_prompt = f"""
You are a SOC analyst AI.

USER QUESTION:
{prompt}

No specific CloudShare data was retrieved for this query. 
Provide general SOC analysis and suggest specific incident IDs or queries.
"""
                        answer = ollama_query(final_prompt)
                    
                except Exception as e:
                    answer = f"""
❌ **Error querying CloudShare NetWitness**

Error: {str(e)}

**Please check:**
1. CloudShare configuration in sidebar
2. Network connectivity to `uvo1gp037tg5ufq0prf.vm.cld.sr`
3. Credentials are correct (try 'Password123!' or 'netwitness')
"""
    else:
        # General SOC question (no NetWitness needed)
        final_prompt = f"""
You are a SOC analyst AI.

USER QUESTION:
{prompt}

Provide helpful security analysis and recommendations.
If incident data would be helpful, mention that real CloudShare data is available.
"""
        answer = ollama_query(final_prompt)
    
    # Add assistant response to history
    st.session_state.chat_history.append({"role": "assistant", "content": answer})
    st.rerun()