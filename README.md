# Linux Process Behavioral Analyzer (LPBA)

LPBA is a research-oriented Linux process monitor that simulates a basic behavioral EDR pipeline.
It captures syscall-driven behavior, scores suspicious activity with transparent heuristics, and exports structured reports for QA and vulnerability research workflows.

## Features

- Syscall-based collection using `strace` (file access, network connect, process execution)
- Suspicious behavior heuristics with additive risk scoring
- JSONL event logs for reproducible analysis
- Pandas-based CSV/JSON reporting
- Bash automation script for one-command setup and execution

## Project Layout

- `lpba_monitor.py`: telemetry collector and heuristic scoring engine
- `analyze_lpba.py`: pandas report generation
- `dummy_malware.c`: harmless suspicious-behavior simulator for testing
- `setup_lpba.sh`: Linux bootstrap and execution automation
- `requirements.txt`: Python dependencies

## Quick Start (Linux/WSL)

```bash
chmod +x setup_lpba.sh
./setup_lpba.sh
```

## Full Test Run (End-to-End)

This section is a reproducible runbook for validating the entire LPBA pipeline:

1. Environment checks
2. Dependency setup
3. Telemetry collection
4. Report generation
5. Output validation
6. Optional QA scenario tests

### 1) Prerequisites

- Linux or WSL2 (Ubuntu recommended)
- Python 3.10+
- `strace`
- `gcc` / build tools

Install system packages:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip strace build-essential
```

### 2) Move into the project

If using WSL and the repo is on Windows drive C:

```bash
cd /mnt/c/Users/<your-user>/Projects/SysInternals-Lite_for_Linux
```

### 3) Run the full automated test

```bash
chmod +x setup_lpba.sh
./setup_lpba.sh
```

What this does:

- Creates `.venv` if missing
- Installs Python dependencies from `requirements.txt`
- Compiles `dummy_malware.c`
- Runs `lpba_monitor.py` against `./dummy_malware`
- Runs `analyze_lpba.py` to generate CSV/JSON reports

### 4) Verify outputs

Expected artifacts in `artifacts/`:

- `events.jsonl`
- `summary.json`
- `lpba_events.csv`
- `lpba_risk_summary.csv`
- `lpba_rule_hits.csv`
- `lpba_analysis_summary.json`

Quick checks:

```bash
ls -lah artifacts
cat artifacts/summary.json
cat artifacts/lpba_analysis_summary.json
```

### 5) Manual mode (collector + analyzer)

Use this if you want to run each stage directly.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

gcc -O2 -Wall -Wextra dummy_malware.c -o dummy_malware
python lpba_monitor.py --out artifacts --cmd ./dummy_malware
python analyze_lpba.py --events artifacts/events.jsonl --out artifacts
```

### 6) Optional QA scenario tests

These map to the QA categories below and help measure false positives/negatives.

False-positive probe (benign temp-file writes):

```bash
python lpba_monitor.py --out artifacts --cmd bash -lc 'for i in $(seq 1 20); do echo ok > /tmp/lpba_benign_$i; done'
python analyze_lpba.py --events artifacts/events.jsonl --out artifacts
```

Potential beaconing probe (repeated outbound connections):

```bash
python lpba_monitor.py --out artifacts --cmd bash -lc 'for i in $(seq 1 10); do nc -z -w1 1.1.1.1 443; done'
python analyze_lpba.py --events artifacts/events.jsonl --out artifacts
```

Sensitive-file access denial probe (non-root):

```bash
python lpba_monitor.py --out artifacts --cmd bash -lc 'cat /etc/shadow >/dev/null 2>&1 || true'
python analyze_lpba.py --events artifacts/events.jsonl --out artifacts
```

### 7) Troubleshooting

- `strace is required`: install with `sudo apt-get install -y strace`
- `gcc is required`: install with `sudo apt-get install -y build-essential`
- Empty or missing trace files: ensure the monitored command actually ran and exited
- If your folder was renamed and old venv paths break execution:

```bash
rm -rf .venv
./setup_lpba.sh
```

Artifacts are generated in `artifacts/`:

- `events.jsonl`
- `summary.json`
- `lpba_events.csv`
- `lpba_risk_summary.csv`
- `lpba_rule_hits.csv`
- `lpba_analysis_summary.json`

## Suspicious Heuristics

- Non-root process attempts to open `/etc/shadow`, `/etc/sudoers`, or `/etc/ssh/*`
- High-rate writes to `/tmp` in short windows
- Repeated outbound `connect` attempts indicating potential beaconing
- Privileged access denials (`EACCES`, `EPERM`)

## QA Research Test Plan Template

### Scope
Validate detection quality, false-positive handling, false-negative resilience, and runtime overhead.

### Test Categories

1. False Positives
- Benign shell scripts writing temp files
- Package manager operations
- Developer toolchains opening many files

2. False Negatives
- Slow beaconing with long intervals
- Low-and-slow temp writes under threshold
- Access through inherited descriptors

3. Performance Overhead
- Idle baseline vs LPBA enabled
- Single high-I/O workload under monitoring
- Concurrent monitored workloads

### Metrics

- Detection precision/recall across scenario sets
- Event ingestion completeness (dropped trace lines)
- CPU and memory overhead of monitor process
- Stability (no monitor crashes under stress)

## GitHub Presentation Guide

To impress a Vulnerability Research lead, include:

1. Threat model and assumptions in README
2. Architecture diagram (collector -> heuristics -> reports)
3. Reproducible demo command and expected outputs
4. QA matrix with false positive/negative evidence
5. Known limitations and evasions (and planned mitigations)
6. Changelog showing iterative heuristic tuning

## Safety Note

Use LPBA only in authorized lab environments. The included sample is for controlled behavior simulation and does not exploit systems.
