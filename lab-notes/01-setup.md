# Lab Note 01 — Initial Setup

**Date:** January 2026  
**Goal:** Build the Azure SOC lab from scratch: VNet, VMs, Log Analytics, and Sentinel.

---

## Step 1 — Create Resource Group

Log in to the Azure portal and navigate to **Resource groups** → **+ Create**.

- Subscription: Pay-As-You-Go
- Resource group name: `rg-soc-lab`
- Region: West Europe

Click **Review + create** → **Create**.

---

## Step 2 — Create Virtual Network

Navigate to **Virtual networks** → **+ Create**.

- Resource group: `rg-soc-lab`
- Name: `vnet-soc-lab`
- Region: West Europe
- Address space: `10.0.0.0/16`

Under **Subnets**, add:
1. `snet-management` — `10.0.1.0/24`
2. `snet-workload` — `10.0.2.0/24`

---

## Step 3 — Create Network Security Groups

Create two NSGs: `nsg-management` and `nsg-workload`.

For `nsg-management` — add inbound rule:
- Priority: 100, Name: AllowRDP-HomeIP
- Source: My home IP address (check via whatismyip.com)
- Destination port: 3389, Protocol: TCP, Action: Allow

Azure automatically creates built-in default deny-all rules at priority **65500** (DenyAllInBound and DenyAllOutBound) — these are pre-existing in every NSG and cannot be deleted or modified. The custom user-configurable rule priority range is 100–4096; all custom rules with a lower number take precedence.

Associate `nsg-management` with `snet-management`.  
Associate `nsg-workload` with `snet-workload`.

---

## Step 4 — Deploy Windows VM (win-sentinel-vm)

Navigate to **Virtual machines** → **+ Create**.

- Resource group: `rg-soc-lab`
- VM name: `win-sentinel-vm`
- Region: West Europe
- Image: Windows Server 2022 Datacenter — Gen2
- Size: Standard_B2s
- Administrator account: set a strong password (stored in password manager)
- Public inbound ports: None (NSG handles access)

**Networking tab:**
- VNet: `vnet-soc-lab`
- Subnet: `snet-management`
- Public IP: Create new (dynamic)
- NIC NSG: None (subnet-level NSG already covers this)

**Management tab:**
- Enable auto-shutdown: 20:00 CET

Click **Review + create** → **Create**. Deployment takes ~3 minutes.

---

## Step 5 — Deploy Linux VM (linux-target-vm)

Same process as above, with:
- VM name: `linux-target-vm`
- Image: Ubuntu Server 22.04 LTS — Gen2
- Size: Standard_B1s
- Authentication: SSH public key (generate with `ssh-keygen -t ed25519 -C "lab-key"`)
- Subnet: `snet-workload`
- Public IP: **None**

---

## Step 6 — Create Log Analytics Workspace

Navigate to **Log Analytics workspaces** → **+ Create**.

- Resource group: `rg-soc-lab`
- Name: `law-soc-lab`
- Region: West Europe
- Pricing tier: Pay-as-you-go

---

## Step 7 — Enable Microsoft Sentinel

Navigate to **Microsoft Sentinel** → **+ Create** → select `law-soc-lab` → **Add**.

Sentinel is now enabled on the workspace.

---

## Step 8 — Configure Data Connectors

In Sentinel, navigate to **Content hub** → search and install:

1. **Windows Security Events** — install, then deploy the data collection rule linking `win-sentinel-vm` to `law-soc-lab`
2. **Azure Activity** — connect (single click; tenant-level)
3. **Microsoft Defender for Cloud** — connect

For Sysmon:
1. RDP into `win-sentinel-vm`
2. Download Sysmon from Sysinternals: `https://learn.microsoft.com/sysinternals/downloads/sysmon`
3. Download SwiftOnSecurity sysmonconfig: `https://github.com/SwiftOnSecurity/sysmon-config`
4. Install: `.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml`
5. Verify service running: `Get-Service Sysmon64`

Back in Azure, create a second DCR that collects the `Microsoft-Windows-Sysmon/Operational` event channel and targets `law-soc-lab`.

---

## Step 9 — Verify Data Ingestion

Wait 10–15 minutes after connecting data sources, then run these queries in Sentinel **Logs**:

```kql
// Check Windows Security Events arriving
SecurityEvent
| where TimeGenerated >= ago(1h)
| summarize count() by EventID
| order by count_ desc
```

```kql
// Check Sysmon data
Event
| where Source == "Microsoft-Windows-Sysmon"
| where TimeGenerated >= ago(1h)
| count
```

Both should return results. If empty after 20 minutes, recheck the DCR → VM association.

---

## Step 10 — Create Analytics Rules

Navigate to Sentinel → **Analytics** → **+ Create** → **Scheduled query rule**.

Create each rule from [`sentinel/analytics-rules.md`](../sentinel/analytics-rules.md). Takes ~30 minutes to set up all five.

---

## Observations

- Initial data ingestion lag was ~12 minutes after the Windows DCR was applied.
- Sysmon Event ID 1 events take longer to appear because they go through the custom `Event` table rather than `SecurityEvent` — this is expected.
- The Linux VM's auth.log starts populating immediately once AMA is installed and the DCR is associated.
- First alert fired approximately 45 minutes after the lab was built: "Brute Force Attack" triggered by my own failed RDP attempts while testing the NSG rule.
