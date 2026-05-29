# Playbook 05 - Data Exfiltration Indicators

**Last Updated:** February 2026
**Severity:** High to Critical
**MITRE ATT&CK:**
- T1048 - Exfiltration Over Alternative Protocol
- T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
- T1041 - Exfiltration Over C2 Channel
- T1567 - Exfiltration Over Web Service
- T1567.002 - Exfiltration to Cloud Storage
- T1020 - Automated Exfiltration

**SLA:** Triage within 10 minutes; containment within 30 minutes if confirmed

---

## Why This Is Always High or Critical

Data exfiltration represents the final objective of most attacks. If confirmed, the attacker has already achieved access and is actively removing data. This is a reportable incident under GDPR Article 33 (supervisory authority notification within 72 hours) and may require customer or partner notification.

---

## Indicators That Trigger This Playbook

- DLP alert: large volume of sensitive file access or copy to removable media
- Network alert: unusually large outbound data transfer from an endpoint or server
- SIEM alert: large number of files accessed by a single account in a short window
- SIEM alert: sensitive file types (zip, rar, tar, csv, xlsx) created in unexpected locations
- Cloud alert: mass download of files from SharePoint or OneDrive
- Network alert: DNS tunnelling indicators or unusual DNS query patterns
- EDR alert: archiving tool (7zip, WinRAR) run against sensitive directories

---

## Pre-Triage Checklist

- [ ] Source system or user account generating the alert
- [ ] Volume of data involved (files and bytes transferred)
- [ ] Destination of the data (external IP, cloud service, USB)
- [ ] Timeframe of the activity
- [ ] Type of data involved (financial, PII, credentials, intellectual property)

---

## Triage Steps

### Step 1 - Quantify the Activity

Before investigating the method, understand the scale.

```kql
// File access events for the suspected user
SecurityEvent
| where EventID == 4663
| where SubjectUserName == "SUSPECTED-USER"
| where TimeGenerated >= ago(4h)
| summarize FilesAccessed = count() by bin(TimeGenerated, 15m)
| render timechart
```

```kql
// Large files created recently (potential staging archive)
DeviceFileEvents
| where DeviceName == "AFFECTED-HOST"
| where Timestamp >= ago(4h)
| where FileSize > 10000000
| project Timestamp, FileName, FolderPath, FileSize, InitiatingProcessFileName, InitiatingProcessAccountName
| order by FileSize desc
```

---

### Step 2 - Identify the Exfiltration Channel

**Outbound network transfer:**

```kql
AzureNetworkAnalytics_CL
| where SrcIP_s == "AFFECTED-HOST-IP"
| where TimeGenerated >= ago(4h)
| where FlowDirection_s == "O"
| summarize TotalBytesSent = sum(OutboundBytes_d) by bin(TimeGenerated, 15m), DestIP_s
| order by TotalBytesSent desc
```

**Cloud storage exfiltration (OneDrive, Dropbox, Google Drive):**

```kql
DeviceNetworkEvents
| where DeviceName == "AFFECTED-HOST"
| where Timestamp >= ago(4h)
| where RemoteUrl has_any ("onedrive.live.com", "dropbox.com", "drive.google.com", "wetransfer.com", "mega.nz")
| project Timestamp, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

**DNS tunnelling indicators:**

```kql
// Unusually long DNS queries to a single domain
DeviceNetworkEvents
| where Timestamp >= ago(4h)
| where DeviceName == "AFFECTED-HOST"
| where strlen(RemoteUrl) > 60
| summarize QueryCount = count() by RemoteUrl
| order by QueryCount desc
```

---

### Step 3 - Identify What Data Was Taken

This is critical for GDPR notification assessment.

- Review file names and paths accessed in audit logs
- Classify the data: PII, financial records, credentials, intellectual property, health data
- Estimate volume: number of records or bytes
- Check if data was compressed or archived before transfer

```kql
// Archive creation events (data staging)
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where RenderedDescription has_any ("7z.exe", "7za.exe", "winrar.exe", "rar.exe", "tar.exe", "zip.exe")
| where Computer == "AFFECTED-HOST"
| where TimeGenerated >= ago(4h)
| project TimeGenerated, RenderedDescription
```

---

### Step 4 - Determine if Exfiltration is Complete or Ongoing

Signs that exfiltration is ongoing: network traffic to the destination is still active; file access events are still occurring; archive tool is still running.

Signs that exfiltration is complete: network connection dropped; no further file access events; archive file has been deleted (Sysmon EID 23 - File Delete).

If activity is ongoing, immediate containment takes priority over completing the investigation.

---

### Step 5 - Attribute the Activity

Determine whether this is an insider threat, a compromised account, or malware-driven exfiltration.

- Check if the user account logged on normally (expected time, device, location)
- Check if the activity aligns with the user role (a developer accessing HR files is suspicious)
- Check if malware indicators are present on the host
- Check for indicators of remote access or C2 connection active during the exfiltration window

---

## Containment Steps

| Action | When | How |
|--------|------|-----|
| Block outbound destination IP or domain | Immediately | Firewall, NSG, proxy |
| Isolate the source endpoint | If malware is involved or account is confirmed compromised | EDR isolate |
| Disable the user account | If insider threat or compromised account is confirmed | Active Directory or Entra ID |
| Preserve evidence | Before any remediation | VM snapshot, network capture |
| Revoke cloud session tokens | If cloud storage was used | Entra ID - revoke sessions |

---

## Escalation Criteria

Escalate immediately to Tier-2, IR team, and management if:
- Personal data (PII, health data, financial) is confirmed exfiltrated - GDPR 72h clock starts
- Volume exceeds 1 GB or more than 1,000 records
- The exfiltration appears automated (high volume, sustained, scripted)
- The destination is a foreign or sanctioned IP jurisdiction
- An insider threat is suspected
- Credentials or authentication tokens were exfiltrated

---

## GDPR Notification Assessment

If personal data was involved, complete this assessment within 2 hours of confirmation:

| Question | Answer | Action |
|----------|--------|--------|
| Were personal data records exfiltrated? | | If yes, notify DPO immediately |
| How many data subjects affected? | | Document |
| What categories of data (name, email, health, financial)? | | Document |
| Is the risk to data subjects high? | | If yes, may need to notify data subjects too |
| Time of detection vs time of breach? | | Document for 72h GDPR clock |

---

## Documentation Template

    INCIDENT SUMMARY
    Incident ID:
    Date/Time:
    Analyst:
    Severity:

    SOURCE OF ACTIVITY
    Hostname:
    User account:
    Insider threat suspected: Yes / No / Unknown

    DATA EXFILTRATED
    Volume (files and/or bytes):
    Data classification (PII / financial / credentials / IP / other):
    File types involved:
    GDPR notification required: Yes / No / Under assessment

    EXFILTRATION CHANNEL
    Method (network / cloud storage / DNS tunnel / USB):
    Destination IP or service:
    Duration of activity:

    STAGING ACTIVITY
    Archive created: Yes / No
    Archive location and name:

    INVESTIGATION FINDINGS
    Malware involved: Yes / No
    Account compromised by external attacker: Yes / No
    Insider threat: Yes / No / Unknown

    CONTAINMENT ACTIONS TAKEN
    Outbound destination blocked: Yes / No
    Endpoint isolated: Yes / No
    User account disabled: Yes / No
    Evidence preserved: Yes / No

    ESCALATED: Yes / No
    Escalated to:
    DPO notified: Yes / No / Not required
    Time:

    FINAL DISPOSITION
    True Positive / False Positive
    Closed by:
    Closed at:
