# Lab Note 03 — Incident Investigation Walkthrough

**Date:** January 2026  
**Scenario:** Simulated insider threat / compromised credential  
**Incident ID:** 67  
**Severity:** High  
**Title:** New Local Administrator Account Created  

---

## Scenario Setup

To practise a more complex investigation, I simulated a compromised account scenario:

1. RDP'd into `win-sentinel-vm` as the lab user
2. Created a new local user account: `net user backdoor P@ssw0rd123! /add`
3. Added it to Administrators: `net localgroup Administrators backdoor /add`

This triggered the **New Local Administrator Account Created** analytics rule (Rule 4) and created a High severity incident in Sentinel.

---

## Step 1 — Incident Intake

Incident details on arrival:

| Field | Value |
|-------|-------|
| Incident ID | 67 |
| Severity | High |
| Status | New |
| Rule | New Local Administrator Account Created |
| Entities | Host: win-sentinel-vm, Account: backdoor |
| Created | 16:14 UTC |

High severity — this goes to the top of the queue. Assign to self and begin immediately.

**Change status:** New → Active

---

## Step 2 — Confirm the Alert is Valid

Run the underlying detection query to confirm the raw evidence:

```kql
// Confirm account creation and group membership change
SecurityEvent
| where EventID in (4720, 4732)
| where Computer == "win-sentinel-vm"
| where TimeGenerated >= ago(1h)
| project TimeGenerated, EventID, TargetUserName, SubjectUserName, MemberName
| order by TimeGenerated asc
```

Results:

| TimeGenerated | EventID | TargetUserName | SubjectUserName | MemberName |
|---------------|---------|----------------|-----------------|------------|
| 16:13:42 UTC | 4720 | backdoor | labuser | — |
| 16:13:43 UTC | 4732 | Administrators | labuser | backdoor |

Confirmed: account `backdoor` was created and added to the local Administrators group by user `labuser` within 1 second.

---

## Step 3 — Investigate the Creating Account

Who is `labuser` and were they acting legitimately?

```kql
// Recent logon activity for labuser
SecurityEvent
| where TargetUserName == "labuser"
| where EventID in (4624, 4625)
| where TimeGenerated >= ago(24h)
| project TimeGenerated, EventID, IpAddress, LogonType, WorkstationName
| order by TimeGenerated desc
```

Results show `labuser` logged on via RDP (LogonType 10) from IP `10.0.1.x` (internal — the lab laptop). This is consistent with normal lab access.

**However** — in a real scenario, the question would be: was this a legitimate admin action or a sign of compromise? We need to check what `labuser` did before creating the account.

---

## Step 4 — Build a Timeline of labuser Activity

```kql
// All events involving labuser in the hour before the incident
SecurityEvent
| where SubjectUserName == "labuser" or TargetUserName == "labuser"
| where TimeGenerated between (datetime(2026-01-16T15:00:00Z) .. datetime(2026-01-16T16:20:00Z))
| project TimeGenerated, EventID, EventLog, Activity, IpAddress, SubjectUserName, TargetUserName
| order by TimeGenerated asc
```

Timeline:

| Time (UTC) | Event | Detail |
|-----------|-------|--------|
| 15:47 | 4624 | labuser logged on via RDP from 10.0.1.x |
| 15:48–16:10 | — | Normal session activity |
| 16:13 | 4720 | labuser created account `backdoor` |
| 16:13 | 4732 | labuser added `backdoor` to Administrators |

---

## Step 5 — Check for Suspicious Processes Around the Incident Time

Did anything unusual run before the account was created? Could indicate malware or a dropper that executed the net.exe commands.

```kql
// Sysmon Process Create events on win-sentinel-vm in the relevant window
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where Computer == "win-sentinel-vm"
| where TimeGenerated between (datetime(2026-01-16T16:05:00Z) .. datetime(2026-01-16T16:20:00Z))
| project TimeGenerated, RenderedDescription
```

Parsed results (key fields extracted from RenderedDescription):

| Time | Process | Parent Process | Command Line | User |
|------|---------|----------------|-------------|------|
| 16:13:41 | net.exe | cmd.exe | `net user backdoor P@ssw0rd123! /add` | labuser |
| 16:13:43 | net.exe | cmd.exe | `net localgroup Administrators backdoor /add` | labuser |

The commands were run interactively from `cmd.exe` as `labuser`. The parent of `cmd.exe` was `explorer.exe` — a legitimate user-initiated shell. No malware indicators.

---

## Step 6 — Check if the New Account Was Used

Did `backdoor` account log on after creation?

```kql
SecurityEvent
| where TargetUserName == "backdoor"
| where EventID in (4624, 4625, 4634)
| where TimeGenerated >= ago(2h)
| project TimeGenerated, EventID, IpAddress, LogonType
```

Results: **0 rows** — the account was created but never logged in. Good sign (in the simulated scenario, I didn't log on as backdoor).

---

## Step 7 — Check Persistence Mechanisms

New admin account could be part of a persistence strategy. Check for other persistence indicators:

```kql
// Registry Run keys modified (Sysmon EID 13)
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| where Computer == "win-sentinel-vm"
| where TimeGenerated >= ago(2h)
| where RenderedDescription contains "CurrentVersion\Run"
| project TimeGenerated, RenderedDescription
```

Result: 0 rows — no Run key modifications.

```kql
// Scheduled task creation (Security Event 4698)
SecurityEvent
| where EventID == 4698
| where Computer == "win-sentinel-vm"
| where TimeGenerated >= ago(2h)
```

Result: 0 rows — no new scheduled tasks.

---

## Step 8 — Response Actions (Simulated)

In a real SOC environment, the response would be:

1. **Immediate:** Disable the `backdoor` account (`net user backdoor /active:no`)
2. **Isolation:** If compromise is suspected, isolate the VM via Defender for Endpoint "Isolate device" action
3. **Password reset:** Force password reset for `labuser` in case credentials were compromised
4. **Escalation:** Escalate to Tier 2 / IR team if malware involvement cannot be ruled out
5. **Evidence preservation:** Take a VM snapshot before any remediation

In the lab, I confirmed the account was mine (simulated), disabled it, and closed the incident.

---

## Step 9 — Close the Incident

- **Status:** Closed
- **Classification:** True Positive
- **Comment:**
  > Confirmed: local account `backdoor` created and added to Administrators group by user `labuser` at 16:13 UTC. Investigation shows commands run interactively from cmd.exe with explorer.exe as grandparent — consistent with user-initiated action, not malware dropper. No logon on the backdoor account observed. No persistence mechanisms (registry Run keys, scheduled tasks) detected. Simulated scenario — labuser is the lab owner. Account disabled. No escalation required.

---

## Lessons Learned

1. Always build a timeline — correlating the account creation event with the preceding logon session and process tree explained the full picture in under 10 minutes.
2. Checking whether the new account was *actually used* is a key triage step — an unused backdoor account may indicate preparation rather than active exploitation.
3. In a real scenario with an unknown `labuser`, this would be escalated immediately pending a call to the user's manager to confirm legitimacy.
4. The Sysmon process tree was invaluable — without it, `net.exe` execution would not have been visible.

---

## Total Investigation Time: ~25 minutes
