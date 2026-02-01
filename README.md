# 🛡️ThreatMinds – AI-Assisted SOC Investigation Chatbot

**ThreatMinds** is an AI-assisted Security Operations Center (SOC) chatbot designed to support security analysts in log investigation, incident triage, MITRE ATT&CK mapping, and remediation guidance.

The system integrates NetWitness log analysis, incident chunking, hybrid AI + rule-based reasoning, and a local Large Language Model (LLM) to automate Level 1–3 SOC investigation workflows while keeping the analyst in control.

Built using Python, Streamlit, and local LLM inference via Ollama, ThreatMinds demonstrates how AI can augment SOC efficiency without fully replacing human analysts.


## 🔧 Feature & Description 
```
Log Ingestion & Retrieval - Retrieves and ingests NetWitness log data from uploaded files or defined sources; Handles structured SOC log formats for downstream analysis. 
Log Parsing & Normalization - Parses NetWitness logs into a normalized internal representation; Extracts key fields such as incident IDs, timestamps, events, and metadata
Incident Chunking - Groups multiple alerts into a single incident context; Prevents LLM context overflow while preserving investigation relevance
Alert Summarization (LLM-Based) - Uses a local Large Language Model (via Ollama) to generate human-readable summaries; Translates raw SOC logs into analyst-friendly explanations 
MITRE ATT&CK Mapping - Maps detected behaviors to MITRE ATT&CK techniques; Provides technique IDs and contextual explanations for analyst reference 
Threat Triage & Severity Classification -  Automatically assigns severity levels to incidents; Supports SOC Level 1 and Level 2 investigation workflows
Rule-Based Detection & Remediation - Applies predefined security rules for known threat patterns; Generates deterministic remediation actions for common incidents
AI-Assisted Remediation Guidance -  Augments rule-based decisions with AI-generated remediation explanations; Helps analysts understand recommended response actions
Streamlit-Based SOC Chatbot Interface - Interactive web-based chatbot for investigation and analysis; Allows analysts to upload logs and ask follow-up questions
```
## 🗂️ Project Structure
```
ThreatMinds/
├── 
│
├── 📂 src/                   # Source code
│   ├── log_analysis.py       # Handles log ingestion(Ryan Ashwin's part)
│   ├── netwitness_parser.py  # Parses and normalizes NetWitness log formats (Ryan Ashwin's part)    
│   ├── log_retrieval.py      # Handles log ingestion(Ryan Ashwin's part)
│   ├── summarizer.py         # Uses LLM to summarize logs(Chris's part)
│   ├── triage.py             # Severity classification(Ryan Ashwin's part)
│   ├── remediation.py        # Generates remediation actions (AI / rule-based/Hybrid) (Ryan Ashwin's part)
│   ├── mitre_mapper.py       # MITRE ATT&CK technique mapping(Chris and team)
│   ├── rule_engine.py       # MITRE ATT&CK technique mapping(Chris and team)
│   ├── json_chunker.py       # Incident chunking to manage large log contexts (Ryan Ashwin's part)


│
├── 📂 api/                   # REST API (FastAPI)
│   └── main.py               # REST endpoint to submit logs
│
├── 📂 ui/                    # Streamlit or Web UI
│   └── app.py

├── 📂 config/                # Config files (API keys, mappings)
│   └── settings.yaml
│
├── 📂 docs/                  # Project documentation
│   ├── architecture.png
│   └── README.md
│
├── .env                      # Environment variables (never push to GitHub)
├── requirements.txt          # Python dependencies
├── README.md                 # GitHub landing page
```


---

## 🚀 How to Run Locally

### 1. 📦 Install Dependencies

```bash
pip install -r requirements.txt
````

> You need Python 3.8 or later.

---
## 🚀 Running the SOC Chatbot Locally

### 1️⃣ Start the Local LLM (Ollama)

```bash
ollama run alienintelligence/cyberaisecurity:latest
````

### 💻 Run the Streamlit UI
```bash
streamlit run ui/chatbot.py

Once the application is running, you can:

📂 Upload NetWitness log files for analysis

💬 Ask investigation and triage questions as a SOC analyst

🛡️ View MITRE ATT&CK mappings and remediation recommendations

The chatbot interface will be available at:
http://localhost:8501



You can now upload logs via the browser and get real-time AI analysis.


## ✨ Credits

Developed by **Christopher Lee Shiven Jian Fu, Ryan Ashwin s/o Ashraf Ali,  Harelingeshwaran S/O Kaliyaperumal**



---
