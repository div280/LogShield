# LogShield

Dual-layer AI forensic framework for detecting
anti-forensic tampering in Windows Event Logs.

## What It Detects
- Deleted log entries (Gap Attack)
- Reordered timestamps (Shuffle Attack)
- Injected fake entries (Injection Attack)
- Audit log cleared (Event ID 1102)
- Audit policy tampered (Event ID 4719)

## Detection Layers
1. HMAC-SHA256 cryptographic integrity chain
2. AI/ML: Isolation Forest + LSTM + Autoencoder

## Operating Modes
1. Forensic Analyzer — upload recovered .evtx or CSV
2. Live Monitor — real-time Windows Event Log watching

## Dataset
- Source: Real Windows Security Event Logs
- 31,658 rows, 14 columns
- Located: data/processed/logshield_dataset_.csv
- Event IDs: 1102, 4719, 4624, 4625, 4688, 4663, 4672

## Team
Final Year Project — CSE Cyber Security
Dayananda Sagar Academy of Technology and Management
VTU, Bangalore
Advisor: Dr. Gerard Deepak

## Live Demo
[Link added after deployment]