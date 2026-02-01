"""
Example usage of the Correlation Engine and Timeline features

This demonstrates how the new features work with the chatbot.
"""

# Example chatbot queries that will now work:

"""
CORRELATION QUERIES (finds all incidents with specific IOCs):
- "Show all cases involving 192.168.31.20"
- "Find incidents with port 80 and domain wshlldmo.com"
- "IP 192.168.1.111 and port 443"
- "What incidents involve 10.0.0.5"
- "Show cases with domain example.com"
- "Find all port 80 activity"

WHAT EACH QUERY DOES:
1. Extracts IPs, ports, and domains from the query
2. Searches the correlation index for matching incidents
3. Returns ALL incidents that contain those IOCs
4. Displays a detailed report with IOC details
5. Provides AI-generated threat analysis

TIMELINE FEATURES:
- The "📅 Incident Timeline" expander shows all incidents chronologically
- Color-coded by priority (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)
- Shows all IOCs, attack tactics, and status for each incident
- Grouped by day for better visualization
- Timestamps help track progression of attacks

CORRELATION INDICATORS:
- The correlation engine automatically finds incidents that share:
  * Source or Destination IPs
  * Ports used
  * Domains contacted
  * Attack tactics/techniques
- Correlation strength = number of shared IOCs
- This helps identify coordinated attacks or lateral movement

EXAMPLE WORKFLOW:
1. Upload your JSON log file with NetWitness incidents
2. The timeline automatically displays all incidents chronologically
3. Ask: "Show cases with port 80" → finds all web-based attacks
4. Ask: "IP 223.25.233.248 and port 80" → finds specific attacker + port combination
5. The correlation engine returns ALL matching incidents with details
6. AI provides threat analysis and recommendations
"""

# Key Features Added:
# ==================
# 
# 1. CorrelationEngine class (correlation_engine.py):
#    - Parses NetWitness JSON format incidents
#    - Extracts IOCs (IPs, ports, domains, files, tactics)
#    - Builds indexed lookup table for fast searching
#    - Supports natural language queries with IOC extraction
#    - Finds related incidents (timeline + shared IOCs)
#    - Generates formatted reports
#
# 2. IncidentTimeline class (incident_timeline.py):
#    - Sorts incidents chronologically
#    - Generates ASCII timeline, Markdown timeline, JSON data
#    - Groups incidents by day
#    - Color-codes by priority and status
#    - Shows all IOCs for each incident
#
# 3. UI Integration (app.py):
#    - Automatically initializes CorrelationEngine when logs are uploaded
#    - Displays timeline in expandable section
#    - Detects correlation queries in chatbot
#    - Extracts IOCs from natural language questions
#    - Shows correlation reports with AI analysis
#    - Works with existing chatbot and analysis features
