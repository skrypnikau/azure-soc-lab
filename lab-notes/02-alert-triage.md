# Lab Note 02 — Alert Triage Walkthrough

**Date:** January 2026  
**Alert:** Brute Force Attack — Windows (Failed Logon Threshold)  
**Severity:** Medium  
**Source:** Custom KQL analytics rule (Rule 1 from sentinel/analytics-rules.md)

---

## Context

This note walks through the process of triaging a brute-force alert as it appeared in the Microsoft Sentinel incident queue. The alert was generated when an external IP address made 23 failed RDP login attempts against `win-sentinel-vm` within a 30-minute window.

---

## Step 1 — Open the Incident in Sentinel

Navigate to **Microsoft Sentinel** → **Incidents**.

The incident appeared at the top of the queue:
- **Title:** Brute Force Attack — Windows (Failed Logon Threshold)
- **Severity:** Medium
- **Status:** New
- **Incident ID:** 42
- **Created:** 14:37 UTC
- **Entities:** 1 IP address, 1 Host

Click the incident to open the detail panel.

---

## Step 2 — Initial Assessment (First 2 Minutes)

Before diving into investigation, note the key facts visible in the incident panel:

| Field | Value |
|-------|-------|
| Triggered rule | Brute Force Attack — Windows (Failed Logon Threshold) |
| Source IP | 45.227.254.x (external) |
| Target host | win-sentinel-vm |
| Target accounts | Administrator, admin, user, test |
| Failed attempts | 23 |
| Time window | 14:07–14:37 UTC |

**Initial assessment:** This looks like an automated credential-stuffing or brute-force tool targeting common account names. The accounts targeted (`admin`, `test`) are not valid accounts on this VM, which suggests a generic scanner rather than a targeted attack.

---

## Step 3 — Investigate the IP Entity

Click **Investigate** to open the entity graph, or click the IP address entity directly.

Actions taken:

1. **Threat intelligence lookup in Sentinel** — check the ThreatIntelligenceIndicator table:
```kql
ThreatIntelligenceIndicator
| where NetworkIP == "45.227.254.x"
| project TimeGenerated, IndicatorId, ThreatType, Confidence, Description
```
Result: No match in Sentinel TI feed.

2. **External lookup** — manually check the IP in:
   - AbuseIPDB: **Confidence of Abuse: 87%** — flagged for SSH scanning and brute force
   - VirusTotal: 3/87 security vendors flagged as malicious
   - Shodan: Port 80 open, running default nginx — likely a compromised VPS used as a scanning node

3. **Check if IP has appeared before:**
```kql
SecurityEvent
| where IpAddress == "45.227.254.x"
| where TimeGenerated >= ago(7d)
| summarize count() by EventID, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```
Result: First appearance of this IP in our logs.

---

## Step 4 — Check for Successful Logon

Critical question: did any logon from this IP succeed?

```kql
SecurityEvent
| where IpAddress == "45.227.254.x"
| where EventID == 4624               // Successful logon
| where TimeGenerated >= ago(2h)
```

Result: **0 rows** — no successful logon from this IP. 

```kql
// Also check for successful logon around the same time from ANY external IP
SecurityEvent
| where EventID == 4624
| where LogonType == 3               // Network logon
| where TimeGenerated between (datetime(2026-01-15T14:00:00Z) .. datetime(2026-01-15T15:00:00Z))
| where IpAddress !startswith "10.0"  // Exclude internal IPs
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType
```

Result: **0 rows** — no external successful logons during the incident window.

---

## Step 5 — Check for Post-Compromise Activity

Even though no successful logon was found, it is good practice to check for lateral movement or other suspicious activity on the host:

```kql
// Any new processes spawned around the incident time
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where Computer == "win-sentinel-vm"
| where TimeGenerated between (datetime(2026-01-15T14:00:00Z) .. datetime(2026-01-15T15:30:00Z))
| project TimeGenerated, RenderedDescription
| order by TimeGenerated asc
```

Result: Only expected processes (Windows Update, Sysmon itself, scheduled tasks). Nothing anomalous.

---

## Step 6 — Determine Disposition

Based on the investigation:

| Finding | Assessment |
|---------|-----------|
| Successful logon? | No |
| IP reputation | High abuse confidence — known scanner |
| Accounts targeted | Generic names; not valid lab accounts |
| Post-compromise activity | None detected |
| Business impact | None |

**Verdict: Benign Positive / Expected Internet Noise**

This is typical internet background noise — automated scanners continuously probe any IP with port 3389 exposed. The environment was not compromised. No accounts were successfully accessed.

---

## Step 7 — Close the Incident

In the incident panel:

- **Status:** Closed
- **Classification:** True Positive — Suspicious Activity (the rule correctly detected the brute force; the attack just didn't succeed)
- **Comment:**
  > Investigated IP 45.227.254.x. AbuseIPDB confidence 87% — known scanner. No successful logon observed. Accounts targeted are default/generic names not present on this system. No post-compromise activity. Internet background noise. Consider adding this IP range to a watchlist for correlation. No escalation required.

---

## Lessons Learned

1. The analytics rule is working correctly — it fired quickly (within 5 minutes of the threshold being crossed).
2. Checking for successful logon as a first step is the most important triage action — it quickly determines if containment is needed.
3. External threat intelligence (AbuseIPDB, VirusTotal) provides useful context in under 2 minutes.
4. For a production SOC, this IP would be added to a blocklist/watchlist and the NSG rule should restrict RDP exposure more aggressively — in a real environment, RDP should never be exposed to the internet.

---

## Time Taken

| Step | Time |
|------|------|
| Initial assessment | 2 min |
| IP investigation | 5 min |
| Successful logon check | 2 min |
| Post-compromise check | 3 min |
| Documentation and close | 3 min |
| **Total** | **~15 min** |
