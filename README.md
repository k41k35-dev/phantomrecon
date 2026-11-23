<p align="center">
  <h1 align="center">⚡ PHANTOM RECON ⚡</h1>
  <p align="center"><b>Unified Attack Surface Discovery & Offensive Threat Profiling Arsenal</b></p>
  <p align="center"><i>Engineered by <b>k41k35</b></i></p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-3.0-gold?style=for-the-badge&logo=target" alt="Version 3.0" />
  <img src="https://img.shields.io/badge/Language-Python%20%7C%20Bash-cyan?style=for-the-badge&logo=gnubash" alt="Languages" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License" />
  <img src="https://img.shields.io/badge/Type-Offensive%20Security-red?style=for-the-badge&logo=kalilinux" alt="Offensive Security" />
</p>

---

## ⚡ Overview

**Phantom Recon** is an automated, high-velocity reconnaissance ecosystem engineered for HackTheBox, OSCP laboratories, and real-world Red Team attack surface profiling.

Rather than running isolated scripts manually, Phantom Recon chains together a multi-tiered pipeline:
1. **Network Discovery & Service Profiling (`nmap_engine.py`):** Adaptive port scanning (TCP/UDP), intelligent timing calibration, dynamic banner grabbing, and automated attack-vector mapping.
2. **High-Speed Directory & Endpoint Fuzzing (`ferodir.sh`):** Smart feroxbuster wrapper with technology autodetection, soft-404 wildcard suppression, extension pivoting, and outlier extraction.
3. **Deep Web Threat Profiling (`web_inspector.py`):** Multi-threaded header auditing, technology stack fingerprinting, endpoint vulnerability mapping, and instant Markdown / JSON reporting.
4. **Unified Orchestration Engine (`phantomrecon`):** Single clean CLI command uniting the entire arsenal.

---

## 🏗️ Architecture

```
phantomrecon/
├── phantomrecon             # Unified CLI Orchestrator & Banner Engine
├── bin/
│   ├── nmap_engine.py       # Port scanner, service profiler & NSE runner
│   ├── ferodir.sh           # One-shot web directory discovery pipeline
│   └── web_inspector.py     # Tech stack & vulnerability correlator
├── docs/
│   ├── ARCHITECTURE.md      # In-depth architectural specification
│   └── OPSEC_AUDIT.md       # OPSEC sanitization & threat modeling log
├── requirements.txt         # Python dependencies
├── pyproject.toml           # Packaging metadata
├── LICENSE                  # MIT License (k41k35)
└── .gitignore               # Offensive artifact exclusions
```

---

## 🚀 Quick Start

### 1. Installation & Prerequisites

Ensure the required dependencies are installed:

```bash
# Clone the repository
git clone https://github.com/k41k35-dev/phantomrecon.git
cd phantomrecon

# Install Python requirements
pip3 install -r requirements.txt

# Ensure core offensive tools are available
# macOS:
brew install nmap feroxbuster jq

# Linux (Debian / Kali / Parrot):
sudo apt install nmap feroxbuster jq
```

Verify your setup with the built-in diagnostic engine:

```bash
./phantomrecon doctor
```

---

## 💻 Usage & Commands

### 🔍 1. Full Attack Surface Scan (Chained Pipeline)
Executes TCP/UDP port mapping, service intelligence analysis, and reactive secondary scanners:

```bash
./phantomrecon full 10.10.11.20
```

### ⚡ 2. Port & Service Reconnaissance (`nmap_engine`)
Direct port discovery with adaptive rate calculation and rich visual reports:

```bash
# Standard full scan
./phantomrecon scan 10.10.11.20

# Quick TCP-only mode (skip UDP)
./phantomrecon scan 10.10.11.20 --fast

# Low & slow evasion mode
./phantomrecon scan 10.10.11.20 --stealth
```

### 🕷️ 3. Web Directory & Endpoint Fuzzing (`ferodir`)
One-shot directory fuzzing with automated wordlist location and technology-adapted extensions:

```bash
# Auto-detects extensions (PHP, ASP.NET, Java, Node, Python) and filters soft-404
./phantomrecon fuzz http://10.10.11.20:8080 -o scan.json
```

### 🕸️ 4. Deep Web Technology & Vulnerability Inspection (`web_inspector`)
Deep threat correlation from Feroxbuster outputs or direct targets:

```bash
# Analyze a Feroxbuster JSON log
./phantomrecon inspect scan.json

# Analyze a direct URL with stealth rate limiting
./phantomrecon inspect http://10.10.11.20:8080 --stealth --markdown report.md
```

---

## 🛡️ OPSEC & Design Principles

- **Zero Hardcoded Environment Paths:** Fully portable path resolution across macOS, Linux (Kali, Parrot, Ubuntu), and Docker containers.
- **Fail-Safe Terminal Orchestration:** Uses `tmux` tabs when active, native macOS terminal tabs if in Ghostty/Terminal, and background daemon logging for headless environments.
- **Aggressive Output Sanitization:** All raw scan artifacts, XML dumps, and wordlists are strictly ignored by `.gitignore` to prevent secret leakage in public repositories.
- **Passive-First Host Validation:** Multi-stage ICMP and TCP connection checks before committing to raw SYN bursts.

---

## 📜 License

Distributed under the **MIT License**. Engineered by **k41k35**. See `LICENSE` for details.
