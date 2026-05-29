# Security Posture Assessment — SOC Lab Environment

**Assessment Date:** February 2026  
**Environment:** Azure SOC Home Lab (`rg-soc-lab`)  
**Assessor:** Yauheni Skrypnikau  
**Methodology:** Manual review against Microsoft Cloud Security Benchmark (MCSB) v1.0 and CIS Azure Foundations Benchmark v2.0

---

## Executive Summary

The lab environment demonstrates a solid foundational security posture for a small, single-person cloud lab. Key strengths include network segmentation via NSGs, centralised logging in Microsoft Sentinel, MFA on the subscription account, and hardened VM configurations. The primary gaps are expected in a lab context — full Azure Policy enforcement and dedicated CSPM tooling are out of scope for cost reasons.

**Overall Rating: GOOD** (lab context — not a production benchmark)

---

## Scope

| In Scope | Out of Scope |
|----------|--------------|
| Azure subscription and `rg-soc-lab` RG | Other subscriptions |
| Two VMs (Windows + Linux) | Production workloads |
| Sentinel and Log Analytics Workspace | Identity (Entra ID tenant-wide) |
| NSGs and VNet | Azure Policy compliance at scale |

---

## Assessment Results by Domain

### 1. Identity and Access Management

| Control | Status | Notes |
|---------|--------|-------|
| MFA enabled on subscription account | Pass | TOTP-based MFA via Microsoft Authenticator |
| No shared accounts | Pass | Single user account for lab |
| Privileged access scoped to RG only | Pass | Contributor role on `rg-soc-lab` only |
| No unused service principals | Pass | Verified via Entra ID app registrations |
| JIT VM access enabled | Pass | Defender for Cloud JIT active for RDP/SSH (Defender for Servers Plan 2) |

### 2. Network Security

| Control | Status | Notes |
|---------|--------|-------|
| VNet segmentation in place | Pass | Management and workload subnets separated |
| NSGs applied at subnet level | Pass | Both subnets have NSGs with explicit deny-all |
| No unrestricted inbound RDP/SSH from Internet | Pass | RDP gated to single home IP; SSH no public IP |
| NSG Flow Logs enabled | Pass | Logs sent to storage and ingested by Sentinel |
| No overly permissive outbound rules | Pass | Outbound allows 443 and 53 only |

### 3. Logging and Monitoring

| Control | Status | Notes |
|---------|--------|-------|
| Centralised log collection active | Pass | Both VMs sending to Log Analytics |
| Security event log collection configured | Pass | Windows Security Events + Linux auth/syslog |
| Sysmon deployed on Windows VM | Pass | Enriched process/network telemetry |
| Analytics rules firing alerts | Pass | 5 custom KQL rules active in Sentinel |
| Defender for Cloud alerts connected | Pass | SecurityAlert table populated |
| Log retention ≥ 90 days | Pass | LAW retention set to 90 days |

### 4. Vulnerability Management

| Control | Status | Notes |
|---------|--------|-------|
| Defender for Servers active | Pass | **Plan 2** on both VMs (JIT, Defender for Endpoint, vulnerability assessment) |
| OS patching current | Pass | All updates applied at build time |
| Defender for Cloud recommendations reviewed | Pass | 7 medium recommendations noted (see below) |
| Vulnerability assessment scan completed | Pass | Qualys agent deployed via Defender for Cloud |

**Open Defender for Cloud Recommendations (medium severity):**

1. Adaptive application controls should be enabled on VMs — *not implemented in lab (lab workloads vary)*
2. Enable Azure Backup for VMs — *not required for lab; no production data*
3. Machine should have a vulnerability findings resolved — *3 findings on Ubuntu: informational kernel hardening params*
4. Endpoint protection solution should be installed on VMs — *Windows Defender active on Windows VM; ClamAV not installed on Linux VM — acceptable for lab*

### 5. Data Protection

| Control | Status | Notes |
|---------|--------|-------|
| No sensitive data stored on VMs | Pass | Lab environment only; no PII or credentials stored |
| Storage account (flow logs) access restricted | Pass | Public access disabled; private access only |
| TLS 1.2 minimum on storage account | Pass | Enforced in storage account settings |

### 6. Incident Response Readiness

| Control | Status | Notes |
|---------|--------|-------|
| Sentinel incident queue monitored | Pass | Daily triage practice |
| Analytics rules create incidents automatically | Pass | All 5 rules set to create incidents on trigger |
| Alert notification configured | Pass | Email notification for High severity incidents |
| Playbooks/runbooks documented | Partial | Informal lab notes; see lab-notes directory |

---

## Risk Register (Lab Context)

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Home IP changes, locking out RDP access | Medium | Low | Dynamic DNS or update NSG rule as needed |
| Unused lab VMs accumulating cost | Low | Low | Auto-shutdown configured |
| Inadvertent data in commits (sub IDs, IPs) | Low | Medium | No Azure portal screenshots committed |
| Lab VM compromised via misconfiguration | Low | Low | No production data; VMs isolated |

---

## Recommendations for Future Improvement

1. **Deploy Azure Policy** — enforce tagging, allowed regions, and required diagnostic settings via Policy as Code
2. **Enable Microsoft Sentinel UEBA** — User and Entity Behaviour Analytics for more advanced detection
3. **Add a honeypot/canary** — deploy an intentionally weak VM with public IP to generate realistic attacker telemetry
4. **Implement Defender for Endpoint** on the Windows VM for EDR telemetry (requires Defender for Servers Plan 2)
5. **Practice threat hunting** — schedule weekly KQL hunting sessions using the MITRE ATT&CK matrix as a guide
