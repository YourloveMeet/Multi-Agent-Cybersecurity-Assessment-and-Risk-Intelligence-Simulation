# CyberSentinel
## Multi-Agent Cybersecurity Assessment & Risk Intelligence Platform

> **Defensive Security First:** CyberSentinel is an autonomous, multi-agent defensive security assessment and risk intelligence platform built with a terminal/CLI-first user experience.

---

## 1. Problem Statement

Traditional vulnerability scanners and network auditing tools often generate overwhelming volumes of unranked, context-free technical findings. Security engineers and operations teams are inundated with lengthy tables of missing headers, port listings, and raw flags without an understanding of:

- Which findings carry immediate, exploitable business risk.
- How asset criticality transforms a moderate technical vulnerability into an urgent operational threat.
- What specific, ordered sequence of remediation actions should be executed first.

Without context and prioritization, security teams suffer from alert fatigue and struggle to address the vulnerabilities that matter most.

---

## 2. Solution: Multi-Agent Intelligence

**CyberSentinel** replaces monolithic scanning with a modular **multi-agent team** where specialized agents collaborate across the security lifecycle:

1. **Reconnaissance Agent**: Safely discovers target boundaries, resolves DNS, verifies reachability, and maps assets.
2. **Web Security Agent**: Non-destructively audits HTTP security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookie security flags (Secure, HttpOnly, SameSite), and information leakage banners.
3. **Configuration Agent**: Inspects TLS certificate validity, remaining lifetime, cryptographic protocol versions (flagging deprecated TLS 1.0/1.1), and audits restricted safe ports for exposed administrative interfaces.
4. **Finding Aggregator**: Normalizes and deduplicates findings across all detection sources, combining observed evidence.
5. **Risk Intelligence Agent**: Contextually correlates raw findings against asset business criticality (`1–10`), computing deterministic risk scores (`0–100`) and assigning remediation priorities (`P0` through `P3`).
6. **Report Agent**: Synthesizes structured executive summaries, human-readable Markdown reports, and machine-readable JSON exports.

---

## 3. Architecture

```text
                    ┌─────────────────────────┐
                    │       Terminal CLI      │
                    │   User / Security Team  │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │      Orchestrator       │
                    └────────────┬────────────┘
                                 │
          ┌──────────────────────┼──────────────────────┐
          │                      │                      │
          ▼                      ▼                      ▼
 ┌────────────────┐     ┌────────────────┐     ┌────────────────┐
 │ Recon Agent    │     │ Web Security   │     │ Configuration  │
 │                │     │ Agent          │     │ Agent          │
 └───────┬────────┘     └───────┬────────┘     └───────┬────────┘
         │                      │                      │
         └──────────────────────┼──────────────────────┘
                                ▼
                     ┌─────────────────────────┐
                     │   Finding Aggregator    │
                     └────────────┬────────────┘
                                  ▼
                     ┌─────────────────────────┐
                     │ Risk Intelligence Agent │
                     └────────────┬────────────┘
                                  ▼
                     ┌─────────────────────────┐
                     │ Priority + Remediation  │
                     └────────────┬────────────┘
                                  ▼
                     ┌─────────────────────────┐
                     │   Report Generation     │
                     │   Markdown / JSON       │
                     └─────────────────────────┘
```

---

## 4. Key Features

- **Terminal-First UX**: Interactive persistent shell (`cybersentinel> `) inspired by modern developer command centers (Claude Code, Codex CLI) featuring live agent status, real-time activity stream, and rich tables.
- **Deterministic Risk Scoring**: Mathematical formula weighting Technical Severity (35%), Exploitability (20%), Exposure Surface (20%), and Asset Criticality (25%), strictly bounded to `[0, 100]`.
- **Prioritized Remediation Queue**: Direct actionable mapping from `P0` (Immediate Attention) to `P3` (Hardening) so engineers know exactly what to patch first.
- **Zero-Dependency Demo Simulation**: Complete deterministic demo environment (`cybersentinel demo`) allowing full pipeline demonstrations without internet access or external credentials.
- **Safe Live Inspection**: Authorized non-destructive auditing for DNS, HTTP/HTTPS headers, TLS certificates, and restricted default ports (`[22, 80, 443, 8080, 8443]`).
- **Comprehensive Reporting**: Generates executive Markdown reports (`./reports/assessment-*.md`) and machine-readable JSON exports (`./reports/assessment-*.json`).
- **Audit History**: Maintains historical assessment snapshots in `~/.cybersentinel/history/`.

---

## 5. Safety and Authorization Model

CyberSentinel is built exclusively for defensive security assessment. It strictly adheres to:

- **No Exploitation Payloads**: No exploit generation, shellcode, brute force, or intrusive scanning.
- **Explicit Authorization**: Live target assessments require explicit user confirmation before initiating network operations.
- **Strict Network Bounds**: Short timeouts, TLS verification, redirect loop limits, and a tightly restricted default port set.

---

## 6. Installation

### Prerequisites
- Python 3.10 or higher

### Setup

```bash
# Clone the repository
git clone https://github.com/YourloveMeet/Multi-Agent-Cybersecurity-Assessment-and-Risk-Intelligence-Simulation.git
cd Multi-Agent-Cybersecurity-Assessment-and-Risk-Intelligence-Simulation

# Create and activate virtual environment
python -m venv .venv

# On Windows (PowerShell):
.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

# Install dependencies and package in editable mode
pip install -r requirements.txt
pip install -e .
```

---

## 7. Usage

### Interactive Shell Mode (Recommended)

Simply launch `cybersentinel` to start the interactive command center:

```bash
cybersentinel
```

```text
╭──────────────────────────────────────────────────────────────╮
│ CYBERSENTINEL                                                │
│ Multi-Agent Cybersecurity Assessment & Risk Intelligence    │
│                                                              │
│ Type 'help' for commands, 'demo' for simulation, 'exit' to   │
│ quit.                                                        │
╰──────────────────────────────────────────────────────────────╯

cybersentinel> demo
cybersentinel> findings
cybersentinel> explain FIND-001
cybersentinel> prioritize
cybersentinel> assets
cybersentinel> report
cybersentinel> export markdown
cybersentinel> export json
cybersentinel> exit
```

### One-Shot CLI Commands

```bash
# Run deterministic offline demo
cybersentinel demo

# Run authorized assessment against a target
cybersentinel assess example.com

# Run quick profile (DNS + HTTP + TLS only)
cybersentinel assess example.com --profile quick

# Export JSON directly to file
cybersentinel demo --json -o reports/demo_result.json

# View past assessment history
cybersentinel history

# View active configuration
cybersentinel config

# View version
cybersentinel version
```

---

## 8. Interactive Shell Commands Reference

| Command | Description |
|:---|:---|
| `demo` | Run deterministic simulation pipeline with simulated multi-agent team |
| `assess <target>` | Run safe authorized assessment against target host or URL |
| `status` | Display active assessment state and execution metadata |
| `agents` | Display agent execution status, duration, and findings counts |
| `findings` | Show findings table (`--severity <S>`, `--priority <P>`, `--agent <A>`) |
| `assets` | View discovered asset inventory and business criticality ratings |
| `risk` | Display executive risk summary card and score breakdown |
| `prioritize` | Display prioritized remediation queue ordered by urgency |
| `explain <id>` | View comprehensive explanation, evidence, impact, and rationale for a finding |
| `recommend <id>` | View actionable remediation instructions for a finding |
| `report` | Render full formatted assessment report to the terminal |
| `export markdown` | Write Markdown report to `./reports/` |
| `export json` | Write structured machine-readable JSON export to `./reports/` |
| `history` | List previous assessment runs stored in `~/.cybersentinel/history/` |
| `config` | View configuration loaded from `~/.cybersentinel/config.toml` |
| `clear` | Clear terminal screen |
| `help` | Show organized command tree |
| `exit` / `quit` | Exit session |

---

## 9. Testing

CyberSentinel includes a complete automated test suite covering models, deterministic scoring, deduplication, agents, and CLI flows:

```bash
# Run full test suite with pytest
pytest
```

---

## 10. License

This project is licensed under the MIT License — see the LICENSE file for details.
