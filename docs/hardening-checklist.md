# VM Hardening Checklist

This checklist documents the hardening steps applied to both virtual machines in the lab. Controls are aligned with **CIS Microsoft Windows Server 2022 Benchmark v1.0** and **CIS Ubuntu Linux 22.04 LTS Benchmark v1.0**.

Legend: ✅ Applied | ⚠️ Partially applied | ❌ Not applicable in lab context

---

## Windows Server 2022 — win-sentinel-vm

### Account Policies
- ✅ Minimum password length set to 14 characters (via Local Security Policy)
- ✅ Password complexity requirements enabled
- ✅ Account lockout threshold: 5 invalid attempts
- ✅ Account lockout duration: 15 minutes
- ✅ Reset account lockout counter after: 15 minutes
- ✅ Administrator account renamed from default "Administrator"
- ✅ Guest account disabled

### Audit Policy (Advanced Audit)
- ✅ Audit Logon/Logoff: Success and Failure
- ✅ Audit Account Logon: Success and Failure
- ✅ Audit Object Access: Failure
- ✅ Audit Privilege Use: Failure
- ✅ Audit Process Creation: Success (generates Security Event ID 4688; note: Sysmon EID 1 is generated independently by the Sysmon driver — the two are complementary, not dependent)
- ✅ Audit Account Management: Success and Failure
- ✅ Audit Policy Change: Success and Failure
- ✅ Audit System Events: Success and Failure

### User Rights Assignment
- ✅ "Access this computer from the network" — restricted to Administrators only
- ✅ "Allow log on locally" — restricted to Administrators only
- ✅ "Deny log on as a batch job" — includes Guest
- ✅ "Debug programs" — empty (removed all users)

### Windows Firewall
- ✅ Windows Defender Firewall enabled on all three profiles (Domain, Private, Public)
- ✅ Inbound connections set to Block (except explicitly allowed)
- ✅ Outbound connections set to Allow
- ✅ RDP (3389) inbound rule scoped to single home IP only

### Services
- ✅ Print Spooler disabled (PrintNightmare mitigation)
- ✅ Remote Registry disabled
- ✅ Telnet disabled
- ✅ SNMP disabled
- ✅ IIS not installed
- ⚠️ SMBv1 disabled — `Set-SmbServerConfiguration -EnableSMB1Protocol $false`

### Windows Updates
- ✅ Windows Update configured — automatic download, manual install (lab preference)
- ✅ All critical and important updates applied at lab build time

### Sysmon Configuration
- ✅ Sysmon v15 installed
- ✅ SwiftOnSecurity sysmon-config applied
- ✅ Events flowing to Log Analytics: EIDs 1 (Process Create), 3 (Network Connect), 7 (Image Load), 11 (File Create), 13 (Registry Value Set), 22 (DNS Query)

### Microsoft Defender Antivirus
- ✅ Real-time protection enabled
- ✅ Cloud-based protection enabled
- ✅ Automatic sample submission enabled
- ✅ PUA (Potentially Unwanted Application) protection enabled

---

## Ubuntu 22.04 LTS — linux-target-vm

### SSH Hardening (`/etc/ssh/sshd_config`)
- ✅ `PermitRootLogin no`
- ✅ `PasswordAuthentication no` — key-based auth only
- ✅ `MaxAuthTries 3`
- ✅ `LoginGraceTime 30`
- ✅ `AllowTcpForwarding no`
- ✅ `X11Forwarding no`
- ✅ `ClientAliveInterval 300`
- ✅ `ClientAliveCountMax 2`
- ✅ SSH port left at 22 (obscurity is not security; NSG restricts source)

### Filesystem
- ✅ `/tmp` mounted with `noexec,nosuid,nodev` options (added to `/etc/fstab`)
- ✅ `/var/tmp` symlinked to `/tmp`
- ✅ Sticky bit set on world-writable directories verified
- ✅ No unowned files found (`find / -nouser -nogroup`)

### User Accounts
- ✅ Root login disabled in SSH
- ✅ No non-system users with UID < 1000 except lab user
- ✅ All user accounts have password aging set (`chage -M 90 -W 14`)
- ✅ `sudo` access limited to lab user only; logged via `/var/log/auth.log`

### Package Management
- ✅ `unattended-upgrades` installed and configured for security updates
- ✅ Unnecessary packages removed: `telnet`, `rsh-client`, `talk`, `ntalk`
- ✅ `auditd` installed and running (supplement to AMA log collection)

### auditd Rules
- ✅ Log all `sudo` executions
- ✅ Log modifications to `/etc/passwd`, `/etc/shadow`, `/etc/group`
- ✅ Log `su` usage
- ✅ Log `chmod`, `chown` calls
- ✅ Log failed access attempts (`-a always,exit -F arch=b64 -S open -F exit=-EACCES`)

### UFW (Uncomplicated Firewall)
- ✅ UFW enabled
- ✅ Default incoming: deny
- ✅ Default outgoing: allow
- ✅ Rule: allow SSH from `10.0.1.0/24` only
- Note: Azure NSG is the primary control; UFW provides defence in depth

### Logging
- ✅ `rsyslog` configured to retain logs for 90 days
- ✅ AMA (Azure Monitor Agent) installed and collecting auth + syslog to LAW

---

## Azure-Level Controls

### Identity and Access Management
- ✅ Multi-Factor Authentication (MFA) enforced on Azure subscription account
- ✅ No service principals or managed identities with Owner/Contributor beyond lab requirement
- ✅ Just-in-time (JIT) VM access enabled via Microsoft Defender for Cloud (requires **Defender for Servers Plan 2**)
- ✅ Azure RBAC: lab user has Contributor on `rg-soc-lab` only, not subscription-wide

### Network Controls
- ✅ NSGs applied at subnet level (defence in depth with VM-level firewall)
- ✅ No public IP on linux-target-vm
- ✅ NSG Flow Logs enabled on both NSGs — sent to storage account → Sentinel
- ✅ DDoS Protection Basic (free tier) active by default

### Monitoring and Alerting
- ✅ Microsoft Defender for Cloud — Defender for Servers **Plan 2** on both VMs (Plan 2 is required for JIT VM Access and Defender for Endpoint integration)
- ✅ Regulatory Compliance dashboard reviewed (Azure Security Benchmark baseline)
- ✅ Activity Log retention set to 90 days
- ✅ Azure Monitor alert rule: alert if VM is deallocated unexpectedly

### Storage (for NSG Flow Logs)
- ✅ Storage account uses TLS 1.2 minimum
- ✅ Public access to containers disabled
- ✅ Soft delete enabled (7-day retention for accidental deletion recovery)
