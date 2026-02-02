# ThreatMinds – AI-Assisted SOC Investigation Chatbot

**ThreatMinds** is an AI-assisted Security Operations Center (SOC) chatbot designed to support security analysts in log investigation, incident triage, MITRE ATT&CK mapping, and remediation guidance.

The system integrates NetWitness log analysis, incident chunking, hybrid AI + rule-based reasoning, and a local Large Language Model (LLM) to automate Level 1–3 and CTI, SOC investigation workflows while keeping the analyst in control.

Built using Python, Streamlit, and local LLM inference via Ollama, ThreatMinds demonstrates how AI can augment SOC efficiency without fully replacing human analysts.


## Feature & Description 
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
## Project Structure
```
ThreatMinds/
├── 
│
├── src/                   # Source code
│   ├── correlation.py        # Finds relationships between incidents based on IPs, domains, ports, and other IOCs(Ryan's part)
│   ├── json_chunker.py       # Incident chunking to manage large log contexts (Ryan's part)
│   ├── log_analysis.py       # Handles log ingestion(Ryan's part)
│   ├── log_retrieval.py      # Handles log ingestion(Ryan's part)
│   ├── mitre_mapper.py       # MITRE ATT&CK technique mapping(Chris' part)
│   ├── netwitness_actions.py # Direct query execution handler (Ryan's part)
│   ├── netwitness_automation.py # Automates incident statistics (MTTA / MTTD / MTTR) (Hare's part)  
│   ├── netwitness_client.py   # Handles authentication, tokens, API calls (Respond & Metadata) (Hare's part)
│   ├── netwitness_manager.py  # Main integration point for NetWitness functionality (Chris/Hare's part)
│   ├── netwitness_metadata.py # Queries sessions and network metadata (IP-based investigations)(Hare's part)
│   ├── netwitness_models.py  # Defines clean data models (IncidentSummary, AlertSummary (Hare's part)
│   ├── netwitness_parser.py  # Parses incident and alert data from NetWitness Platform exports(Ryan's part)
│   ├── netwitness_queries.py # Fetches incidents, alerts, relationships, and formats summaries (Hare's Part)
│   ├── ollama_client.py      # Local LLM wrapper: sends prompts to Ollama + returns responses consistently (Chris's part)
│   ├── persona.py            # Coded SOC analysts roles and responsibilities(Chris's part)
│   ├── pipeline.py           # End-to-end ingestion pipeline: parse incident → chunk → return retriever object for AI/correlation (Ryan's part)
│   ├── remediation.py        # Generates remediation actions (AI / rule-based/Hybrid) (Ryan's part)
│   ├── rule_engine.py        # Loads remediation rules + matches conditions against incident events to trigger persona-specific actions Ryan's part)
│   ├── summarizer.py         # Uses LLM to summarize logs(Ryan's/Chris' part)
│   ├── threat_explainer.py   # Converts detection output into “what happened / why it matters / next steps” narrative (Ryan's/Chris' part)
│   ├── triage.py             # Severity classification(Chris's part)
│
│
│
├── api/                   # REST API (FastAPI)
│   └── main.py               # REST endpoint to submit logs
│
├── ui/                    # Streamlit web user interface
│   └── app.py

├── config/                # Config files (API keys, mappings)
│   └── settings.yaml
│

│   └── README.md
│
├── .env                      # Environment variables (never push to GitHub)
├── requirements.txt          # Python dependencies
├── README.md                 # GitHub landing page
```


---

## 🚀 How to Run Locally

### Install Dependencies

```bash
pip install -r requirements.txt
````

> You need Python 3.12 or later.

---
##  Running the SOC Chatbot Locally

### Start the Local LLM (Ollama)

```bash
ollama run alienintelligence/cyberaisecurity:latest

                  OR
                 
Running the SOC Chatbot on GPU Cloud Instances(e.g. Lambda Cloud)
- Use the Installation guide.docx
````

### Run the Streamlit UI
```bash
streamlit run ui/app.py


Once the application is running, you can:

- Upload NetWitness log files for analysis

- Ask investigation and triage questions as a SOC analyst

- View MITRE ATT&CK mappings and remediation recommendations

The chatbot interface will be available at:
http://localhost:8501
````


You can now upload logs via the browser and get real-time AI analysis.


## Credits

Developed by **Christopher Lee Shiven Jian Fu, Ryan Ashwin s/o Ashraf Ali,  Harelingeshwaran S/O Kaliyaperumal**

## Acknowledgments

This project was inspired by a developer's repository:https://github.com/Ninadjos/SOCGPT-AI-Powered-SOC-Assistant.git

This repository gave the team a starting reference and the system has been developed and modified significantly to meet the objectives and scope of the Final Year Project


---
