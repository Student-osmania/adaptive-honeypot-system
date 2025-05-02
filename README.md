# 🛡️ Adaptive AI-Enhanced Honeypot System

**An industry-grade, intelligent honeypot platform** that simulates vulnerable systems, tracks adversarial behavior, performs real-time GPT-based analysis, and dynamically adapts decoys using reinforcement feedback. It integrates MITRE ATT&CK threat mapping, IOCs extraction, and mock services (SSH, SQL DB, ICS, Cloud) to cover a wide spectrum of attack vectors.

## 📌 Table of Contents

- [Features](#features)
- [Architecture Overview](#architecture-overview)
- [Directory Structure](#directory-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Modules Explained](#modules-explained)
- [Mock Services](#mock-services)
- [AI Analysis & RL](#ai-analysis--rl)
- [Threat Intelligence & IOCs](#threat-intelligence--iocs)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Logging & Dashboards](#logging--dashboards)
- [License](#license)

## 🚀 Features

- ✅ Realistic file-based and service-level honeypots
- 🤖 GPT/GPT4All behavioral analysis with risk scoring
- 🔁 Reinforcement Learning-style feedback for adaptive decoy strategies
- 🔐 Fake credentials, SSH keys, and deceptive shell environments
- 🛰️ ICS, SQL DB, and Cloud mock environments
- 🧠 MITRE ATT&CK technique tagging and IOC mapping
- 📊 Structured logging with support for Elasticsearch & Kibana dashboards
- 📁 Modular, production-ready Python codebase

## 🧬 Architecture Overview

```
+-------------------+          +--------------------------+
|   Attacker        |  --->    | Honeypot File/Service    |
+-------------------+          +--------------------------+
                                     |
                                     v
                          +------------------------+
                          | Behavioral Monitor     |
                          |  - File events         |
                          |  - Network traffic     |
                          +------------------------+
                                     |
                                     v
+--------------------------+    +-------------------------+
| GPT4All / OpenAI GPT-4   |<---| rl_gpt_adapter.py       |
| Behavior Classifier      |    | - Prompt builder        |
|                          |    | - Reinforcement loop    |
+--------------------------+    +-------------------------+
                                     |
                                     v
                          +------------------------+
                          | MITRE Mapper + IOC     |
                          | - Extract indicators   |
                          | - Map to tactics       |
                          +------------------------+
                                     |
                                     v
                          +------------------------+
                          | Logger + Dashboards    |
                          +------------------------+
```

## 📂 Directory Structure

```
honeypot_project/
│
├── core/
│   ├── deployment.py         # Deploys/rotates decoys
│   ├── gan_generator.py      # Optional: GPT-based decoy gen
│   ├── logger.py             # Structured logging
│   ├── openai_decision.py    # Hooks GPT output + mapping
│   ├── watcher.py            # Monitors file/dir activities
│   ├── mitre_mapper.py       # Maps logs to ATT&CK framework
│   └── ioc_parser.py         # Extracts IPs/domains/hashes
│
├── mock_services/
│   ├── ssh_server.py         # Fake SSH with shell
│   ├── sql_server.py         # Mock SQL DB
│   ├── ics_emulator.py       # Industrial Control System sim
│   └── cloud_service.py      # Simulated cloud storage
│
├── ai_model/
│   └── rl_gpt_adapter.py     # GPT-based behavior analysis
│
├── data/
│   ├── behavior_logs.csv     # Structured attacker logs
│
├── decoys/
│   ├── pre_generated/        # Decoy file pool
│   └── deployed/             # Active decoys in system
│
├── logs/
│   ├── honeypot.log          # Human-readable log
│   └── honeypot.json         # Structured log for parsing
│
├── models/
│   └── prompt_templates/     # GPT prompt samples
│
├── utils/
│   ├── file_utils.py         # Metadata ops, hashing, etc.
│   ├── helpers.py            # Shared utils
│   └── timing.py             # Scheduler, log rotation
│
├── config.py                 # Config: paths, thresholds
├── main.py                   # Entry point
├── requirements.txt          # Dependencies
└── README.md                 # You're here
```

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/adaptive-honeypot.git
cd adaptive-honeypot

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure your OpenAI API key or set up GPT4All local model
cp config.example.py config.py
# Edit config.py with your preferred settings
```

## 🚀 Usage

```bash
# Start the honeypot system
python main.py

# To run specific components only
python main.py --services ssh,sql
python main.py --no-ai  # Run without AI analysis

# View logs in real-time
tail -f logs/honeypot.log
```

## 🧩 Modules Explained

1. **main.py** – Launches all components in threads
2. **watcher.py** – File system monitor using watchdog
3. **openai_decision.py** – Sends logs to LLM for analysis
4. **logger.py** – Stores logs to JSON, CSV, log files
5. **deployment.py** – Places decoy files & rotates on detection
6. **mitre_mapper.py** – Maps actions to ATT&CK TTPs
7. **ioc_parser.py** – Parses IPs, hashes, domains from logs

## 🧪 Mock Services

| Service      | Port | Description                               |
| ------------ | ---- | ----------------------------------------- |
| SSH          | 2222 | Fake shell, password logging, shell traps |
| SQL DB       | 3306 | Accepts fake SQL queries, logs behaviors  |
| ICS Emulator | 502  | Simulates SCADA/Modbus-style traffic      |
| Cloud        | 8080 | Dummy file API (upload/download traps)    |

## 🧠 AI Analysis & RL

The system uses either OpenAI GPT-4 or GPT4All local models to:
- Analyze attacker logs
- Detect behavioral patterns
- Assign a risk score (0–10)
- Suggest honeypot response (rotate decoy, alert, ignore)
- Log IOCs (IPs, hashes, domains)

Reinforcement loop adjusts decoy deployment or IP bans based on model feedback.

## 🕵️ Threat Intelligence & IOCs

- Extract indicators from logs using regex/NLP
- Store in structured formats for correlation
- Auto-tag using MITRE TTPs

## 🔐 MITRE ATT&CK Mapping

Each behavioral event is mapped to MITRE techniques using:
- Log keywords
- GPT classification
- Known IOC patterns

Example: "Brute-force login attempt" → T1110 (Credential Access)

## 📈 Logging & Dashboards

Logs are stored in:
- logs/honeypot.log – Human-readable format
- logs/honeypot.json – Structured format for dashboards

Compatible with:
- Elasticsearch + Kibana
- Splunk
- SIEM tools

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📞 Contact

Project Link: [https://github.com/yourusername/adaptive-honeypot](https://github.com/yourusername/adaptive-honeypot)
