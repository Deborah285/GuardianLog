# GuardianLog — Enterprise Security Operations Center

![Version](https://img.shields.io/badge/version-2.0-cyan) ![Status](https://img.shields.io/badge/status-active-brightgreen) ![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20Docker-blue) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

GuardianLog is a self-contained, browser-based Security Operations Center (SOC) dashboard built for monitoring, analyzing, and responding to authentication threats in real time. Designed as a solo self-taught development project, it demonstrates end-to-end security engineering, from log ingestion and SQLite persistence to AI-assisted threat analysis and production script generation.

---

## Features

### Dashboard & Simulation Center
A live multi-host SOC environment with status cards, real-time threat feeds, and a simulation engine for testing detection logic without requiring a live production system.

### SQLite DB Explorer
An integrated database viewer for querying and inspecting the `guardian_soc.db` log store directly from the browser. No external database client required.

### Log Ingestion Wizard
A guided interface for configuring log source paths, detection thresholds, time windows, IP whitelists, and alert webhook endpoints.

### Manual Log Parser
A terminal-style interface for parsing raw authentication log entries on demand which is useful for forensic investigation of individual events.

### Production Script Exporter
Generates deployment-ready scripts in three formats based on your configured settings:

| Target | Output |
|--------|--------|
| Linux | Python monitoring daemon (`guardian_server.py`) |
| Windows | PowerShell background service (`guardian_service.ps1`) |
| Docker | Compose stack with volume-mounted log streaming (`docker-compose.yml`) |

### AI Threat Analyst
An AI-powered analyst module for interpreting threat patterns, summarizing anomalies, and providing remediation guidance from ingested log data.

---

## Tech Stack

- **Frontend:** HTML5, Tailwind CSS, Font Awesome, Fira Code / Inter (Google Fonts)
- **Storage:** SQLite (`guardian_soc.db`) via browser-side integration
- **Backend Scripts:** Python 3 (Linux), PowerShell (Windows)
- **Deployment:** Docker Compose support included
- **Integrations:** AbuseIPDB API, custom webhook alerting

---

## Getting Started

GuardianLog is a single-file application. No build step or server is required to run the dashboard.

### Running Locally

1. Download `guardianlog_security_center_updated.html`
2. Open it in any modern browser (Chrome, Firefox, Edge)
3. Navigate between modules using the sidebar

### Live Demo (GitHub Pages)

If deployed via GitHub Pages, the dashboard is accessible at:

```
https://<Deborah285>.github.io/<GuardianLog>/
```

---

## Deployment (Production Backend)

Use the **Production Exporter** tab to generate a backend script configured to your environment, then deploy it as follows:

**Linux**
```bash
python3 guardian_server.py
```

**Windows (install as background service)**
```powershell
.\guardian_service.ps1 -Install
```

**Docker**
```bash
docker compose up -d
```

---

## Detection Logic

GuardianLog monitors authentication logs for the following threat patterns:

- **Brute Force Detection** — Flags IPs exceeding a configurable failed login threshold within a rolling time window
- **Credential Compromise** — Identifies successful logins from IPs with a prior failure history
- **IP Reputation Enrichment** — Cross-references suspicious IPs against the AbuseIPDB threat intelligence database
- **Whitelist Support** — Excludes trusted IPs from alerting to reduce false positives

---

## Project Background

This project was developed independently as part of a self-directed journey into cybersecurity engineering and full-stack development (vibe coding). GuardianLog reflects practical application of SOC concepts including log analysis, threat detection, database persistence, and alert automation, built entirely without formal training.

---

## License

This project is released under the [MIT License](LICENSE).

---

> Built with dedication by a self-taught developer. Contributions, feedback, and stars are welcome.
