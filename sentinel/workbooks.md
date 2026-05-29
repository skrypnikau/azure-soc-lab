# Microsoft Sentinel — Workbooks

Three custom workbooks were created to provide visual dashboards for the lab environment. Workbooks are built using the Azure Monitor Workbook framework with embedded KQL queries.

---

## Workbook 1: SOC Overview Dashboard

**Purpose:** Single-pane-of-glass view of the lab's security activity. Used as the daily starting point for triage.

**Sections:**

### 1.1 — Alert Summary (Last 24h)
KQL tile showing count of alerts by severity (High / Medium / Low / Informational) as a bar chart.

```kql
SecurityAlert
| where TimeGenerated >= ago(24h)
| summarize AlertCount = count() by AlertSeverity
| order by AlertCount desc
```

### 1.2 — Top Alert Rules Fired (Last 7 Days)
Table showing which analytics rules are generating the most alerts — useful for spotting overly noisy rules.

```kql
SecurityAlert
| where TimeGenerated >= ago(7d)
| summarize Count = count() by AlertName, AlertSeverity
| order by Count desc
| take 10
```

### 1.3 — Failed Logon Trend (Windows)
Line chart over 7 days showing failed logon events per hour.

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated >= ago(7d)
| summarize FailedLogons = count() by bin(TimeGenerated, 1h)
| render timechart
```

### 1.4 — Open Incidents by Status
Pie chart of open incidents by status (New / Active / Closed).

---

## Workbook 2: Windows Security Events Deep Dive

**Purpose:** Detailed view of Windows Security log events for investigation and threat hunting.

**Sections:**

### 2.1 — Logon Activity by User
```kql
SecurityEvent
| where EventID in (4624, 4625, 4648)
| where TimeGenerated >= ago(24h)
| summarize
    SuccessfulLogons = countif(EventID == 4624),
    FailedLogons = countif(EventID == 4625),
    ExplicitCreds = countif(EventID == 4648)
    by TargetUserName
| where TargetUserName !endswith "$"
| order by FailedLogons desc
```

### 2.2 — Process Creation Events (Sysmon)
Table of all process creation events in the last 24h, filterable by user and process name. Helps identify unusual child processes.

### 2.3 — Account Management Events
Timeline of account creation, deletion, and group membership changes (Event IDs 4720, 4726, 4732, 4733).

### 2.4 — Security Policy Changes
Events 4719 (System audit policy changed) and 4907 (Auditing settings on object changed) — any changes here are high-interest.

---

## Workbook 3: Network Activity Monitor

**Purpose:** Visualise network traffic patterns using NSG Flow Logs. Useful for identifying unusual connections or port scans.

**Sections:**

### 3.1 — Top Source IPs (Inbound, Last 24h)
Bar chart of inbound connection attempts by source IP — quickly surfaces scanning activity.

```kql
AzureNetworkAnalytics_CL
| where TimeGenerated >= ago(24h)
| where FlowDirection_s == "I"
| summarize ConnectionCount = count() by SrcIP_s
| top 20 by ConnectionCount
```

### 3.2 — Allowed vs Denied Flows
Stacked area chart over 24h showing allowed vs denied NSG flows. A spike in denied flows may indicate a scan.

```kql
AzureNetworkAnalytics_CL
| where TimeGenerated >= ago(24h)
| summarize
    Allowed = countif(FlowStatus_s == "A"),
    Denied = countif(FlowStatus_s == "D")
    by bin(TimeGenerated, 30m)
| render areachart
```

### 3.3 — Destination Port Distribution
Pie chart of destination ports in inbound flows. Expected to see 3389 (RDP) and occasional noise; unexpected ports are flagged.

### 3.4 — Geo Map of Source IPs
World map tile (using `geo_info_from_ip_address()` or Maxmind GeoIP) showing geographic distribution of inbound IPs. Purely informational — helps contextualise where probes originate.

---

## Notes

- Workbooks are saved as private workbooks in the Sentinel workspace (not shared — single-user lab).
- Workbook 1 is pinned to the Azure dashboard for quick access.
- The time range parameter on all workbooks is dynamic (user can select Last 24h, 7d, 30d).
