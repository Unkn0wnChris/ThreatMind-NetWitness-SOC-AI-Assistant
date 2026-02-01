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
├── 📂 data/                  # Sample logs, input data
│   └── example_logs.txt
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


```


---

### 3. 🧪 Run Log Analysis Pipeline

```bash
python run_pipeline.py
```

It will read logs from `data/example_logs.txt` and email the summarized report.

---

### 4. 🌐 Run REST API

```bash
uvicorn api.main:app --reload
```

Then POST logs to `http://localhost:8000/analyze-log`.

---

### 5. 💻 Run the Streamlit UI

```bash
streamlit run ui/app.py
```

You can now upload logs via the browser and get real-time AI analysis.

---

## 🧠 LLM Experiment Notebook

Use `notebooks/llm_experiments.ipynb` to:

* Test different GPT prompts
* Compare summarization and remediation quality
* Build custom templates for new log types

---

## 📤 Sample Email Output

```
Subject: SOCGPT Alert Report

🔍 Summary: Detected PowerShell command execution from suspicious source.
🚦 Severity: High
📋 MITRE ATT&CK: T1059 – Command and Scripting Interpreter
🛡️ Remediation: Block the source IP and inspect endpoint for post-exploitation activity.
```

---

## 🛡️ MITRE ATT\&CK Integration

Currently supported mappings:

| Log Pattern    | Mapped Technique                          |
| -------------- | ----------------------------------------- |
| `powershell`   | T1059 – Command and Scripting Interpreter |
| `login failed` | T1110 – Brute Force                       |
| Others         | `Unknown Technique`                       |

Expand `mitre_mapper.py` for additional coverage.

---

## 📦 Docker (Optional)

You can also run this as a container:

```bash
docker build -t socgpt .
docker run -p 8501:8501 socgpt
```




---

## ✨ Credits

Developed by **Ryan Ashwin, Christopher Lee, Harelingwesharan**



---
