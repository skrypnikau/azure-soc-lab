# Microsoft Sentinel — Custom Analytics Rules

All rules are scheduled analytics rules using KQL. They run against the Log Analytics Workspace (`law-soc-lab`) and create incidents in the Sentinel incident queue when triggered.

---

## Rule 1: Brute Force Attack — Windows (Failed Logon Threshold)

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing  
**Severity:** Medium  
**Run frequency:** Every 5 minutes  
**Lookback:** 30 minutes  
**Threshold:** 10 failed logons from the same source IP within the lookback window  

```kql
// Brute Force: multiple failed logons against Windows VM
SecurityEvent
| where EventID == 4625                          // Failed logon
| where TimeGenerated >= ago(30m)
| summarize
    FailedAttempts = count(),
    TargetAccounts = make_set(TargetUserName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IpAddress, Computer
| where FailedAttempts >= 10
| extend
    TimespanMinutes = datetime_diff('minute', LastAttempt, FirstAttempt),
    AccountsTargeted = array_length(TargetAccounts)
| project
    Computer,
    IpAddress,
    FailedAttempts,
    AccountsTargeted,
    TargetAccounts,
    FirstAttempt,
    LastAttempt,
    TimespanMinutes
| order by FailedAttempts desc
```

**Alert logic:** Alert fires when `FailedAttempts >= 10` from a single `IpAddress` to a single `Computer`.  
**Entity mapping:** IpAddress → IP entity; Computer → Host entity.  
**Incident auto-creation:** Yes.

---

## Rule 2: Suspicious Logon — Logon Outside Business Hours

**MITRE ATT&CK:** T1078 — Valid Accounts  
**Severity:** Low  
**Run frequency:** Every 15 minutes  
**Lookback:** 20 minutes  
**Notes:** Designed to flag after-hours access. In a lab, "business hours" are set to 08:00–22:00 CET (07:00–21:00 UTC).

```kql
// Successful interactive or network logon outside defined hours
SecurityEvent
| where EventID == 4624                           // Successful logon
| where LogonType in (2, 3, 10)                   // Interactive, Network, RemoteInteractive
| where TimeGenerated >= ago(20m)
| extend HourUTC = hourofday(TimeGenerated)
| where HourUTC < 7 or HourUTC >= 21             // Outside 08:00–22:00 CET
| where AccountType == "User"                     // Exclude computer accounts
| where TargetUserName !endswith "$"              // Exclude machine accounts
| project
    TimeGenerated,
    Computer,
    TargetUserName,
    IpAddress,
    LogonType,
    HourUTC,
    AuthenticationPackageName
```

---

## Rule 3: Port Scan Detection via NSG Flow Logs

**MITRE ATT&CK:** T1046 — Network Service Discovery  
**Severity:** Medium  
**Run frequency:** Every 10 minutes  
**Lookback:** 15 minutes  
**Threshold:** Single source IP connecting to ≥ 15 distinct destination ports within the window  

```kql
// Port scan: one source IP hitting many ports on the target
AzureNetworkAnalytics_CL
| where TimeGenerated >= ago(15m)
| where SubType_s == "FlowLog"                    // Exclude topology/other record types
| where FlowType_s == "ExternalPublic" or FlowType_s == "MaliciousFlow"
| where L4Protocol_s == "T"                       // TCP only
| summarize
    DistinctPorts = dcount(DestPort_d),
    PortList = make_set(DestPort_d),
    FlowCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SrcIP_s, DestIP_s                          // DestIP_s is the single destination IP field
| where DistinctPorts >= 15
| project
    SrcIP_s,
    DestIP_s,
    DistinctPorts,
    PortList,
    FlowCount,
    FirstSeen,
    LastSeen
| order by DistinctPorts desc
```

---

## Rule 4: New Local Administrator Account Created

**MITRE ATT&CK:** T1136.001 — Create Account: Local Account  
**Severity:** High  
**Run frequency:** Every 5 minutes  
**Lookback:** 10 minutes  

```kql
// Local account creation followed by addition to Administrators group
let AccountCreation = SecurityEvent
| where EventID == 4720                           // User account created
| where TimeGenerated >= ago(10m)
| project
    CreationTime = TimeGenerated,
    NewAccount = TargetUserName,
    UserSid = TargetSid,
    CreatedBy = SubjectUserName,
    Computer;
let AddedToAdmins = SecurityEvent
| where EventID == 4732                           // Member added to security-enabled local group
| where TimeGenerated >= ago(10m)
| where TargetUserName == "Administrators"
| project
    AddedTime = TimeGenerated,
    AddedAccountSid = MemberSid,
    Computer;
AccountCreation
| join kind=inner AddedToAdmins
    on Computer
| where UserSid == AddedAccountSid
| project
    Computer,
    NewAccount,
    UserSid,
    CreatedBy,
    CreationTime,
    AddedTime
```

---

## Rule 5: Suspicious Process Execution — Living off the Land (LoL)

**MITRE ATT&CK:** T1059.001 (PowerShell), T1059.003 (Windows Command Shell), T1218 (System Binary Proxy Execution)  
**Severity:** Medium  
**Run frequency:** Every 5 minutes  
**Lookback:** 15 minutes  
**Data source:** Sysmon Event ID 1 (Process Create) via `Event` table  

```kql
// Detect known LOLBins launched with suspicious parent processes
// Uses Sysmon EID 1 RenderedDescription format: "Image: C:\path\process.exe"
let SuspiciousProcesses = dynamic([
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe", "installutil.exe",
    "bitsadmin.exe", "wmic.exe", "odbcconf.exe"
]);
let SuspiciousParents = dynamic([
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe"
]);
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1                              // Process Create
| extend
    ProcessName = tostring(extract(@"(?:Image|OriginalFileName):\s*(?:[^\\\n]+\\)*([^\\\n]+\.exe)", 1, RenderedDescription)),
    ParentProcess = tostring(extract(@"ParentImage:\s*(?:[^\\\n]+\\)*([^\\\n]+\.exe)", 1, RenderedDescription)),
    CommandLine = tostring(extract(@"CommandLine: (.+?)(?:\n|$)", 1, RenderedDescription)),
    User = tostring(extract(@"User: (.+?)(?:\n|$)", 1, RenderedDescription))
| where TimeGenerated >= ago(15m)
| where tolower(ProcessName) in (SuspiciousProcesses)
| where tolower(ParentProcess) in (SuspiciousParents)
| project
    TimeGenerated,
    Computer,
    User,
    ProcessName,
    ParentProcess,
    CommandLine
| order by TimeGenerated desc
```

---

## Notes on Rule Tuning

- Rule 1 threshold was tuned upward from the default (5 → 10 failed logons) to reduce false positives from legitimate repeated authentication attempts in the lab environment.
- Rule 3 threshold is set at ≥ 15 distinct ports; the `SubType_s == "FlowLog"` filter was added to exclude topology records from AzureNetworkAnalytics_CL and ensure only actual flow data is evaluated.
- Rule 2 is informational in a single-user lab (the only user is me) but included to practise the workflow of suppressing expected alerts.
- Rule 5 requires Sysmon to be installed and the Event table to be populated — verified working. Regex patterns match Sysmon EID 1 `RenderedDescription` format (`Image: C:\path\process.exe`).
- **ASIM Recommendation (Rule 5):** In production environments, parsing Sysmon events directly from raw events is resource-intensive and fragile to changes in event formatting. It is highly recommended to normalise these logs using the **Microsoft Sentinel Advanced Security Information Model (ASIM)** parsers—specifically `imProcessCreate`—to ensure rule vendor-independence and significantly higher query performance.
