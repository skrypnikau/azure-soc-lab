# Azure SOC Home Lab

![Platform](https://img.shields.io/badge/Platform-Microsoft%20Azure-0078D4?logo=microsoftazure&logoColor=white)
![SIEM](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4?logo=microsoft&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Focus](https://img.shields.io/badge/Focus-SOC%20%2F%20Blue%20Team-blue)

A hands-on home lab built in Microsoft Azure to practise real-world Security Operations Centre (SOC) workflows: ingesting logs, writing detection rules, triaging alerts, and running incident investigations — all within a controlled cloud environment.

---

## What This Lab Does

This lab simulates a small enterprise environment hosted in Azure. It is designed to:

- Generate realistic security telemetry (failed logins, port scans, suspicious process executions)
- Collect and centralise logs in a **Log Analytics Workspace** connected to **Microsoft Sentinel**
- Trigger custom **KQL analytics rules** that fire alerts when suspicious patterns are detected
- Walk through the full SOC Tier-1 workflow: alert → triage → investigation → close or escalate

The lab is intentionally kept small (two VMs) to minimise cost while covering the most important detection scenarios a SOC analyst encounters on the job.

---

## Architecture Overview

```
Internet
    │
    ▼
Azure Virtual Network (10.0.0.0/16)
├── Subnet: management (10.0.1.0/24)
│       └── Windows Server 2022 VM  [win-sentinel-vm]
│               NSG: allow RDP from home IP only
│
└── Subnet: workload (10.0.2.0/24)
        └── Ubuntu 22.04 VM  [linux-target-vm]
                NSG: allow SSH from management subnet only

Log Analytics Workspace ◄──── Diagnostic settings from both VMs
        │
        ▼
Microsoft Sentinel (SIEM/SOAR)
        ├── Analytics Rules (KQL)
        ├── Workbooks (dashboards)
        ├── Incidents queue
        └── Automation (Playbooks / Logic Apps)
```

Full architecture documentation is in [`docs/architecture.md`](docs/architecture.md).

---

## What Was Configured

### Azure Infrastructure
- Resource group `rg-soc-lab` in West Europe region
- Virtual Network with two subnets and strict NSG rules
- Two VMs: Windows Server 2022 (monitoring/jump host) and Ubuntu 22.04 (target)
- Azure Defender for Servers (Plan 1) enabled on both VMs
- Boot diagnostics and guest OS diagnostics enabled

### Log Collection
- Windows Security Event logs (Event IDs: 4624, 4625, 4648, 4688, 4720, 4732, 4768, 4769)
- Windows Sysmon (installed manually — config based on SwiftOnSecurity template)
- Linux auth logs via AMA (Azure Monitor Agent) — `/var/log/auth.log`, `/var/log/syslog`
- Azure Activity Log (resource-level changes)
- NSG Flow Logs → Storage Account → Sentinel connector
- Microsoft Defender for Cloud alerts connector

### Microsoft Sentinel
- Workspace created and connected to Log Analytics
- Data connectors enabled: Windows Security Events via AMA, Sysmon, Azure Activity, Defender for Cloud
- Five custom KQL analytics rules (see [`sentinel/analytics-rules.md`](sentinel/analytics-rules.md))
- Three workbooks created (see [`sentinel/workbooks.md`](sentinel/workbooks.md))
- Incident queue used daily for triage practice

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Microsoft Azure | Cloud infrastructure hosting |
| Microsoft Sentinel | SIEM / SOAR platform |
| Log Analytics Workspace | Log storage and KQL query engine |
| Sysmon | Enhanced Windows process/network telemetry |
| Azure Monitor Agent (AMA) | Log collection from VMs |
| Microsoft Defender for Cloud | Vulnerability assessment and alerts |
| KQL (Kusto Query Language) | Writing detection and hunting queries |
| Azure NSGs | Network access control |
| Azure Activity Log | Audit trail for resource changes |

---

## Skills Demonstrated

- **Cloud security architecture** — designing a segmented VNet with least-privilege NSG rules
- **Log management** — configuring data connectors and log ingestion pipelines in Sentinel
- **KQL** — writing analytics rules for brute-force, suspicious logins, and port scan detection
- **Alert triage** — working through the Sentinel incident queue, assigning severity, investigating entities
- **Incident investigation** — correlating events across Windows Security logs, Sysmon, and network flows
- **VM hardening** — applying CIS Benchmark controls to Windows Server and Ubuntu
- **Documentation** — writing structured lab notes and investigation reports

---

## Lab Notes

Step-by-step notes from building and using the lab:

| Note | Description |
|------|-------------|
| [`lab-notes/01-setup.md`](lab-notes/01-setup.md) | Initial Azure setup, VM deployment, Sentinel onboarding |
| [`lab-notes/02-alert-triage.md`](lab-notes/02-alert-triage.md) | Triaging a brute-force alert in the Sentinel incident queue |
| [`lab-notes/03-incident-investigation.md`](lab-notes/03-incident-investigation.md) | Full incident investigation walkthrough |

---

## Hardening & Security Posture

- [`docs/hardening-checklist.md`](docs/hardening-checklist.md) — CIS-aligned hardening steps applied to both VMs
- [`docs/security-posture.md`](docs/security-posture.md) — Baseline security posture assessment of the lab environment

---

## Screenshots

> Screenshots are not committed to the repository to avoid any accidental exposure of subscription IDs or internal IP addresses. The lab notes reference the key screens at each step.

---

## Cost

This lab runs at approximately **€15–25/month** with both VMs on B1s SKUs and auto-shutdown at 20:00 daily. Microsoft Sentinel has a 10 GB/day free data ingestion tier which covers this lab comfortably.

---

## Author

**Yauheni Skrypnikau** — Cybersecurity Analyst  
Focused on cloud security, SOC operations, and blue-team tooling.  
*   **LinkedIn:** [linkedin.com/in/skrypnikau](https://www.linkedin.com/in/skrypnikau)
*   **GitHub:** [github.com/skrypnikau](https://github.com/skrypnikau)
