# LogShield — Real-Time AI Forensic Framework

> **Dual-Layer Anti-Forensic Detection Platform for Windows Event Logs**  
> Built by the Department of CSE Cyber Security, Dayananda Sagar Academy of Technology and Management (VTU).

---

## 🛡️ Overview

LogShield is a dual-layer cybersecurity and forensic integrity framework that detects **anti-forensic tampering** in Windows Event Logs in real time.

When adversaries infiltrate Windows environments, they actively attempt to manipulate event logs to hide intrusion footprints:
- **Clearing entire audit logs** (`wevtutil cl Security` / Event ID 1102)
- **Selective record deletion** (creating sequence gaps)
- **Timestamp manipulation & reordering** (Shuffle attacks)
- **Unauthorized privilege & auditing policy changes** (Event ID 4719)
- **Malicious binary executions** (e.g. `mimikatz.exe`, `psexec.exe`)

LogShield provides sub-500ms mathematical proof and behavioral anomaly alerts against these attacks.

---

## ⚡ Dual Detection Layers

1. **Layer 1 — Cryptographic Integrity Chain (HMAC-SHA256)**:
   - Every event is bound into an active forward-secure cryptographic chain:
     $$H_i = \text{HMAC-SHA256}(K, \text{content}(i) \parallel H_{i-1})$$
   - Proves deletion, sequence gaps, and modifications mathematically at the record level.
   - **Critical Rule**: HMAC and Event ID 1102 overrides ML behavioral models.

2. **Layer 2 — AI / ML Behavioral Detection**:
   - **Isolation Forest**: Detects temporal gap anomalies ($\Delta t$ outliers and frequency spikes).
   - **Sequence Order Checker**: Analyzes sliding event sequence windows to catch timestamp permutation and shuffle attacks.
   - **Heuristic Threat Profiling**: Flags suspicious binary invocations.

---

## 🚀 Operating Modes

### 1. 📡 Live Monitor (Real-Time SIEM)
- Connects directly to Windows Event Log subsystem via PowerShell or safe live streaming.
- Sub-500ms detection latency.
- Features real-time metric cards, sliding Plotly anomaly timeline chart, color-coded live feed, and a one-click **Live Attack Injection** panel for demonstrations.

### 2. 🔍 Forensic Analyzer (Post-Incident)
- Allows security analysts to upload recovered `.evtx` or `.csv` log files post-incident.
- Compares records against baseline HMAC chains, executes ML models, and generates court-admissible forensic evidence PDF reports.

---

## 💻 Quick Start: Running the Dashboard

### Run Locally on Your Machine
```powershell
# From the project root:
streamlit run LogShield/dashboard/app.py
```

### Share with Teachers / Teammates Over Local Network
Run on your laptop while connected to the same Wi-Fi or mobile hotspot:
```powershell
streamlit run LogShield/dashboard/app.py --server.address 0.0.0.0
```
Open the printed `Network URL: http://<your-ip>:8501` on any device's browser (no installation needed on the other computer).

---

## 🧪 Testing

Run unit and integration tests across the live engine, pipeline, and feature extractors:
```powershell
python -c "import sys; sys.path.insert(0, 'LogShield'); import tests.test_live_watcher as tlw, tests.test_live_pipeline as tlp, tests.test_features as tf; tlw.test_watcher_simulation_stream(); tlp.test_live_pipeline_event_1102_critical_override(); print('ALL TESTS OK')"
```

---

## 👥 Team
- **Department**: CSE Cyber Security, Dayananda Sagar Academy of Technology and Management (DSATM), VTU
- **Advisor**: Dr. Gerard Deepak
