# AI Honeypot Barrier

AI-powered defensive layer that observes live traffic, clusters suspicious connections, and silently redirects attackers into a Cowrie honeypot where their behaviour is logged for analysis.

## Features
- Live packet capture via Scapy with JSON persistence.
- KMeans clustering to label suspicious versus benign flows.
- Optional iptables NAT redirection into Cowrie (dry-run enabled by default).
- Cowrie JSON log parsing to surface attacker commands and downloads.
- Modular pipeline (`main.py`) wired through a YAML configuration file.

## Repository Layout
```
+-- config/               # Pipeline configuration
+-- data/                 # Capture + processed artefacts (gitignored in practice)
+-- logs/                 # Runtime logs
+-- src/
¦   +-- capture/          # Packet sniffing
¦   +-- clustering/       # Traffic analytics
¦   +-- honeypot/         # iptables + log parsing tools
¦   +-- pipeline/         # Orchestration logic
¦   +-- utils/            # Shared helpers
+-- main.py               # CLI entry point
```

## Getting Started
1. Create a Python virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows
   pip install -r requirements.txt
   ```
2. Review `config/defaults.yaml` and adjust interfaces, capture limits, and honeypot settings for your lab network.
3. Run the pipeline (requires root/administrator privileges for packet capture and iptables):
   ```bash
   sudo python main.py --config config/defaults.yaml
   ```

## Configuration Highlights
- `paths`: Locations for captured traffic, clustered output, Cowrie log, and summaries.
- `capture`: Interface, packet limit, and BPF filter passed to Scapy. Toggle `enabled` to reuse existing captures.
- `clustering`: KMeans parameters for traffic grouping.
- `honeypot`: Control NAT redirection. Leave `enable_redirects` off for dry testing.
- `analysis`: Enable or disable Cowrie log parsing.

## Operational Flow
1. **Capture** – Scapy sniffs packets and writes `data/raw/traffic_capture.json`.
2. **Cluster** – Metadata is featurised and grouped; suspicious flows are tagged in `data/processed/clustered_traffic.json`.
3. **Redirect** – Suspicious source IPs can be diverted to Cowrie via iptables DNAT.
4. **Analyse** – Cowrie log entries (if available) are summarised to `data/processed/cowrie_summary.json`.

## Next Steps
- Feed Cowrie attacker behaviours back into clustering model for adaptive learning.
- Extend with a Flask dashboard for live metrics and rule management.
- Harden deployment scripts for production gateways (systemd, health checks, log rotation).
