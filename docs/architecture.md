# Lab Architecture

## Overview

The lab consists of a single Azure subscription with a dedicated resource group (`rg-soc-lab`) deployed in the **West Europe** region. All resources are within one Virtual Network to keep egress costs minimal while still practising realistic network segmentation.

---

## Virtual Network Design

| Component | Value |
|-----------|-------|
| VNet name | `vnet-soc-lab` |
| Address space | `10.0.0.0/16` |
| Region | West Europe |
| Resource group | `rg-soc-lab` |

### Subnets

| Subnet | CIDR | Purpose |
|--------|------|---------|
| `snet-management` | `10.0.1.0/24` | Windows jump host / Sentinel monitoring VM |
| `snet-workload` | `10.0.2.0/24` | Linux target VM — receives simulated attacks |

---

## NSG Rules

### NSG: `nsg-management`
Attached to `snet-management`.

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowRDP-HomeIP | Inbound | My home IP /32 | Any | 3389 | TCP | Allow |
| 200 | AllowHTTPS-Outbound | Outbound | Any | Any | 443 | TCP | Allow |
| 300 | AllowDNS-Outbound | Outbound | Any | Any | 53 | UDP | Allow |
| 65500 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

### NSG: `nsg-workload`
Attached to `snet-workload`.

| Priority | Name | Direction | Source | Destination | Port | Protocol | Action |
|----------|------|-----------|--------|-------------|------|----------|--------|
| 100 | AllowSSH-FromMgmt | Inbound | `10.0.1.0/24` | Any | 22 | TCP | Allow |
| 200 | AllowHTTPS-Outbound | Outbound | Any | Any | 443 | TCP | Allow |
| 65500 | DenyAllInbound | Inbound | Any | Any | Any | Any | Deny |

> Rationale: SSH to the Linux VM is only permitted from the management subnet, forcing all access through the Windows jump host. This mirrors a segmented enterprise design and reduces the attack surface.

---

## Virtual Machines

### win-sentinel-vm (Windows Server 2022)

| Parameter | Value |
|-----------|-------|
| VM Size | Standard_B2s (2 vCPU, 4 GB RAM) |
| OS | Windows Server 2022 Datacenter |
| Private IP | 10.0.1.4 |
| Public IP | Dynamic (allocated on start) |
| Subnet | snet-management |
| Disk | 128 GB Standard SSD (OS), no data disk |
| Extensions | AzureMonitorWindowsAgent, MicrosoftAntimalware |

Software installed manually:
- Sysmon v15 (SwiftOnSecurity config)
- Windows Admin Center

### linux-target-vm (Ubuntu 22.04 LTS)

| Parameter | Value |
|-----------|-------|
| VM Size | Standard_B1s (1 vCPU, 1 GB RAM) |
| OS | Ubuntu 22.04 LTS |
| Private IP | 10.0.2.4 |
| Public IP | None (no public IP assigned) |
| Subnet | snet-workload |
| Disk | 30 GB Standard SSD (OS) |
| Extensions | AzureMonitorLinuxAgent |

---

## Log Analytics Workspace

| Parameter | Value |
|-----------|-------|
| Name | `law-soc-lab` |
| SKU | Pay-as-you-go (new workspace 31-day free trial: 10 GB/day; standard rates apply after trial) |
| Retention | 90 days |
| Region | West Europe |

Data collection rules (DCRs) configured:
- `dcr-windows-security-events` — collects Windows Security event log at "Common" level
- `dcr-linux-syslog` — collects auth, syslog, and kern facilities from Ubuntu VM
- `dcr-sysmon` — collects Microsoft-Windows-Sysmon/Operational event channel

---

## Microsoft Sentinel Workspace

Sentinel is enabled on top of `law-soc-lab`. Connectors active:

| Connector | Data Types |
|-----------|-----------|
| Windows Security Events via AMA | SecurityEvent |
| Sysmon via AMA | Event (Sysmon channel) |
| Azure Activity | AzureActivity |
| Microsoft Defender for Cloud | SecurityAlert |
| NSG Flow Logs (via Storage) | AzureNetworkAnalytics_CL |

---

## Data Flow Diagram

```
[Windows VM]                    [Linux VM]
     │  Sysmon + Security Events      │  auth.log + syslog
     │  via AMA                       │  via AMA
     ▼                                ▼
[Data Collection Rules (DCR)]──────────┘
     │
     ▼
[Log Analytics Workspace: law-soc-lab]
     │
     ▼
[Microsoft Sentinel]
     ├── Analytics Rules (KQL) ──► Alerts ──► Incidents
     ├── Threat Intelligence
     ├── Workbooks (dashboards)
     └── Automation (Logic Apps)
```

---

## Cost Controls

- Both VMs have **Auto-shutdown** configured at 20:00 CET daily
- VM SKUs kept at B-series (burstable) — cheapest suitable option
- No Azure Bastion (cost saving — RDP directly via NSG rule instead)
- Sentinel new workspace trial (10 GB/day ingest for first 31 days) is sufficient for lab-scale telemetry; standard pay-as-you-go rates apply after the trial period
