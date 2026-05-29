# Playbook 03 — Lateral Movement

**Last Updated:** February 2026
**Severity:** High to Critical
**MITRE ATT&CK:**
- T1021.001 — Remote Services: Remote Desktop Protocol
- T1021.002 — Remote Services: SMB/Windows Admin Shares
- T1021.006 — Remote Services: Windows Remote Management
- T1550.002 — Use Alternate Authentication Material: Pass the Hash
- T1550.003 — Use Alternate Authentication Material: Pass the Ticket
- T1563.002 — Remote Service Session Hijacking: RDP Hijacking
**SLA:** Immediate triage; escalation within 30 minutes if confirmed

---

## Why This Is High/Critical Severity

Lateral movement means an attacker has already established a foothold and is actively expanding their access within the environment. The attack is no longer contained to a single system. Rapid response is essential to prevent the attacker from reaching high-value targets (domain controllers, file servers, databases).

---

## Indicators That Trigger This Playbook

- SIEM alert: unusual authentication pattern (one host authenticating to many other hosts in a short window)
- Alert: use of administrative shares (ADMIN$, C$, IPC$) from a non-standard source
- Alert: WMI or WinRM execution on a remote host
- Alert: Pass-the-Hash indicators (NTLM authentication where Kerberos would be expected, Event ID 4624 LogonType 3 with NtLmSsp)
- EDR alert: PsExec, WMIExec, SMBExec, or similar remote execution tool detected
- Unusual RDP connections between workstations (workstation-to-workstation RDP is rare in most environments)

---

## Triage Steps

### Step 1 — Identify the Source (Originating Compromised Host)

Lateral movement starts from somewhere — identify which host is the source of the suspicious lateral activity.

```kql
// Find hosts making many outbound authentication attempts (lateral movement source)
SecurityEvent
| where EventID == 4624
| where LogonType == 3                        // Network logon — typical for lateral movement
| where TimeGenerated >= ago(2h)
| where AuthenticationPackageName == "NTLM"  // NTLM used in PtH attacks
| summarize
    TargetHosts = dcount(Computer),
    LogonCount = count()
    by SubjectDomainName, SubjectUserName, IpAddress
| where TargetHosts > 3
| order by TargetHosts desc
```

Also look for WMI/WinRM-based movement:

```kql
// WMI process creation on remote hosts (Sysmon EID 1 with WmiPrvSE parent)
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription contains "WmiPrvSE.exe"
| where TimeGenerated >= ago(2h)
| project TimeGenerated, Computer, RenderedDescription
```

---

### Step 2 — Map the Movement (Build a Host Graph)

Identify which hosts the attacker has touched. This defines the blast radius.

```kql
// All successful network logons from the suspected source IP/host
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10)
| where IpAddress == "SOURCE-IP" or WorkstationName == "SOURCE-HOST"
| where TimeGenerated >= ago(4h)
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), Count = count()
    by Computer, TargetUserName, LogonType, AuthenticationPackageName
| order by FirstSeen asc
```

Document each host reached — these all need investigation.

---

### Step 3 — Check for Pass-the-Hash Indicators

Pass-the-Hash (PtH) is one of the most common lateral movement techniques. Key indicators:

- Event ID 4624, LogonType 3, AuthenticationPackageName = NTLM (especially for accounts that normally use Kerberos)
- The NTLM logon does not have a corresponding Kerberos ticket request (no Event ID 4768/4769 for that session)
- Source host is a non-DC, and target is a server that requires admin privileges

```kql
// Pass-the-Hash indicator: NTLM network logon without Kerberos context
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where TimeGenerated >= ago(2h)
| where TargetUserName !endswith "$"          // Exclude machine accounts
| project TimeGenerated, Computer, TargetUserName, IpAddress, WorkstationName, AuthenticationPackageName
```

---

### Step 4 — Check for Remote Execution Tools

Attackers use tools like PsExec, Impacket's wmiexec, or built-in Windows tools (WMI, WinRM, AT, sc.exe) to execute commands remotely.

```kql
// Suspicious remote execution tools (Sysmon process creation)
let RemoteExecTools = dynamic(["psexec.exe", "psexesvc.exe", "wmic.exe", "winrm.cmd", "at.exe"]);
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any (RemoteExecTools)
| where TimeGenerated >= ago(2h)
| project TimeGenerated, Computer, RenderedDescription
```

Look also for new services being installed remotely (common PsExec indicator):

```kql
// New service installation — often used by PsExec (Security Event 4697)
SecurityEvent
| where EventID == 4697          // Service installed
| where TimeGenerated >= ago(2h)
| project TimeGenerated, Computer, ServiceName, ServiceFileName, ServiceAccount
```

---

### Step 5 — Determine Credential Scope

**What credentials does the attacker have?**

- If a single service account is being used across many hosts, that account's hash or ticket was stolen
- Check where that account's credentials were last legitimately used
- Determine if it is a domain admin or has equivalent privileges — if yes, the entire domain may be at risk

```kql
// Find all recent uses of the suspected compromised account
SecurityEvent
| where TargetUserName == "COMPROMISED-ACCOUNT" or SubjectUserName == "COMPROMISED-ACCOUNT"
| where EventID in (4624, 4625, 4648, 4768, 4769)
| where TimeGenerated >= ago(12h)
| summarize EventCount = count() by EventID, Computer, bin(TimeGenerated, 1h)
| order by TimeGenerated desc
```

---

### Step 6 — Identify Target of Lateral Movement

Where is the attacker trying to go? Look at the pattern of hosts reached:

- Are they moving toward the domain controller?
- Are they targeting file servers or backup systems?
- Are they attempting to reach systems with sensitive databases?

This context determines escalation urgency.

---

## Containment Steps

**Immediate containment (do within the first 30 minutes):**

| Action | How |
|--------|-----|
| Isolate the source host | EDR "Isolate device" or Azure portal VM stop |
| Isolate all compromised hosts identified in Step 2 | Same — each host in the blast radius |
| Disable the compromised credential | Disable account in Active Directory / Entra ID |
| Block movement via NTLM if PtH confirmed | Temporary policy to require Kerberos (coordinate with IT) |
| Alert domain admins | If domain admin credentials may be compromised — this is critical |

---

## Escalation Criteria

**Escalate immediately to Tier-2 and IR team if:**

- Any domain controller has been reached
- Domain admin credentials are suspected compromised
- The attacker has reached more than 3 hosts
- Evidence of data staging or exfiltration from any reached host
- Attacker appears to be targeting backup systems or security tooling

---

## Documentation Template

```
INCIDENT SUMMARY
Incident ID:
Date/Time:
Analyst:
Severity:

AFFECTED HOSTS (blast radius)
Source host:
Additional compromised hosts:
Hosts suspected to be targeted but not yet reached:

CREDENTIAL ANALYSIS
Compromised account(s):
Privilege level (standard user / admin / domain admin):
Method (PtH / PtT / plaintext / unknown):

LATERAL MOVEMENT TIMELINE
[List each hop with timestamp, source host, destination host, method]

INVESTIGATION FINDINGS
Remote execution tools detected: Yes / No
Domain controller reached: Yes / No
Domain admin credentials compromised: Yes / No
Evidence of data staging: Yes / No

CONTAINMENT ACTIONS TAKEN
[ ] Source host isolated
[ ] All compromise hosts isolated
[ ] Compromised account(s) disabled
[ ] Domain admins notified

ESCALATED: Yes / No
Time escalated:
Escalated to:

FINAL DISPOSITION
Status at time of handoff to IR team:
Closed by:
Closed at:
```
