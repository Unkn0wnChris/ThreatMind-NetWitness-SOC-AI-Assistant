# 🛡️ThreatMinds – AI-Assisted SOC Investigation Chatbot

**ThreatMinds** is an AI-assisted Security Operations Center (SOC) chatbot designed to support security analysts in log investigation, incident triage, MITRE ATT&CK mapping, and remediation guidance.

The system integrates NetWitness log analysis, incident chunking, hybrid AI + rule-based reasoning, and a local Large Language Model (LLM) to automate Level 1–3 SOC investigation workflows while keeping the analyst in control.

Built using Python, Streamlit, and local LLM inference via Ollama, ThreatMinds demonstrates how AI can augment SOC efficiency without fully replacing human analysts.


## 🔧 Feature & Description 
```
Log Analysis - Parses and ingests raw logs from Suricata, Zeek, Windows Event Logs, etc. 
Alert Summarization - Uses OpenAI's GPT to generate readable summaries for raw technical logs. 
Threat Triage - Automatically prioritizes alerts by analyzing severity and behavior. 
Remediation Suggestions - Recommends first response actions like IP blocking or user account isolation. 
MITRE ATT&CK Mapping - Maps detected behavior to MITRE ATT&CK techniques (e.g., T1059). 
Analyst Q&A (Explain Threats) -  Analysts can ask follow-up questions about logs or threats. 
Slack/Email Notifications - Sends analysis reports directly to the SOC via email or chat platforms. 
REST API & Web UI -  Offers both an API and Streamlit-based UI to interact with the system.
```
## 🗂️ Project Structure
```
SOCGPT/
├── 
│
├── 📂 src/                   # Source code
│   ├── log_analysis.py       # Handles log ingestion(Ryan Ashwin's part)
│   ├── summarizer.py         # Uses LLM to summarize logs(Chris's part)
│   ├── triage.py             # Severity classification(Ryan Ashwin's part)
│   ├── remediation.py        # Suggests first response actions(Chris' part)
│   ├── mitre_mapper.py       # MITRE ATT&CK technique mapping(Chris and team)
│   ├── threat_explainer.py   # Q&A with LLM for analyst(Chris' part)
│   └── notifier.py           # Email / Slack integration(Chris' part)
│
├── 📂 api/                   # Optional: REST API (FastAPI / Flask)
│   └── main.py               # REST endpoint to submit logs
│
├── 📂 ui/                    # Optional: Streamlit or Web UI
│   └── app.py
│
├── 📂 notebooks/             # Jupyter notebooks for prototyping
│   └── llm_experiments.ipynb
│
├── 📂 config/                # Config files (API keys, mappings)
│   └── settings.yaml
│
├── 📂 docs/                  # Project documentation
│   ├── architecture.png
│   └── README.md
│
├── .env                      # Environment variables (never push to GitHub)
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container setup
├── README.md                 # GitHub landing page
└── run_pipeline.py           # Main script to test end-to-end flow 
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


```bash
streamlit run ui/chatbot.py

Once the application is running, you can:

📂 Upload NetWitness log files for analysis

💬 Ask investigation and triage questions as a SOC analyst

🛡️ View MITRE ATT&CK mappings and remediation recommendations

The chatbot interface will be available at:
http://localhost:8501



### 💻 Run the Streamlit UI

```bash
streamlit run ui/app.py
```

You can now upload logs via the browser and get real-time AI analysis.


## ✨ Credits

Developed by **Christopher Lee Shiven Jian Fu, Ryan Ashwin s/o Ashraf Ali,  Harelingeshwaran S/O Kaliyaperumal**



---
