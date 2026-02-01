"""
Persona Comparison Tool
Shows how different analyst roles provide different analysis for the same log
"""

import streamlit as st

st.set_page_config(page_title="Persona Comparison", layout="wide")
st.title("Analyst Persona Comparison")

st.markdown("""
This page shows how SOCGPT adapts its analysis based on analyst role.

## How It Works

When you select a different analyst persona in the sidebar, the AI analysis adjusts:
- **Summary detail level** - L1 gets brief summaries, L3 gets in-depth context
- **Severity sensitivity** - L3 and CTI flag medium threats as high
- **Remediation scope** - L1 escalates, L3 provides comprehensive response plans

---
""")

# Create comparison table
from src.persona import Analyst_Persona

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("### L1 SOC Analyst")
    st.markdown(Analyst_Persona["L1 SOC Analyst"])
    st.markdown("**Focus:**")
    st.markdown("- Quick triage\n- Obvious threats\n- Escalation decisions")

with col2:
    st.markdown("### L2 SOC Analyst")
    st.markdown(Analyst_Persona["L2 SOC Analyst"])
    st.markdown("**Focus:**")
    st.markdown("- Deep investigation\n- IOC extraction\n- TTP correlation")

with col3:
    st.markdown("### L3 SOC Analyst / IR")
    st.markdown(Analyst_Persona["L3 SOC Analyst / IR"])
    st.markdown("**Focus:**")
    st.markdown("- Root cause analysis\n- Containment strategy\n- Threat hunting")

with col4:
    st.markdown("### CTI Analyst")
    st.markdown(Analyst_Persona["Cyber Threat Intelligence Analyst (CTI)"])
    st.markdown("**Focus:**")
    st.markdown("- Threat actor profiles\n- Attribution\n- Knowledge sharing")

st.divider()

# Example comparison
st.markdown("## Analysis Scope by Role")

scope_data = {
    "Analysis Type": ["Summary", "Triage", "Remediation"],
    "L1": ["2-3 sentences, immediate threats", "Standard sensitivity", "1 action (escalate)"],
    "L2": ["3-4 sentences, context", "Standard sensitivity", "2-3 investigation steps"],
    "L3": ["4-5 sentences, RCA", "High sensitivity", "Comprehensive response"],
    "CTI": ["4-5 sentences, TTP", "High sensitivity", "IOC & attribution focus"]
}

import pandas as pd
df = pd.DataFrame(scope_data)
st.table(df)

st.divider()

st.markdown("""
##  Try It Yourself

1. Go back to the main app
2. **Change the analyst role** in the sidebar
3. **Upload the same log** or refresh the page
4. Notice how the analysis changes in:
   - **Summary** - Different detail levels
   - **Remediation** - Different scope and recommendations
   - **Triage** - Different sensitivity to threats

### Example Scenario

Same malware alert analyzed by different roles:

**L1 Analysis:**
```
Summary: Malware detected on endpoint. Action: Isolate system.
Triage: High
Remediation: Escalate to L2 for investigation
```

**L3 Analysis:**
```
Summary: Trojan detected, likely C2 beacon. System already compromised. 
RCA needed. Response: Isolate immediately, preserve logs, hunt for lateral movement.
Triage: High
Remediation: 
1. Isolate system from network
2. Preserve memory dump and event logs
3. Block C2 domains in firewall
4. Hunt for similar IoCs across network
5. Check domain admin activity
```

This demonstrates role-appropriate depth and decision-making!
""")
