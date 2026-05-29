# Incident Report Template

**Instructions:** Fill out this template during or immediately after triage. This is the formal record of the incident and your investigation.

---

## 1. Incident Summary

| Field | Value |
|-------|-------|
| Incident ID | |
| Date and Time (UTC) | |
| Detection Source | SIEM rule / AV alert / user report / external notification |
| Analyst | |
| Severity | Critical / High / Medium / Low |
| Status | Open / In Progress / Escalated / Closed |
| Incident Type | Phishing / Brute Force / Lateral Movement / Malware / Data Exfil / Other |
| MITRE ATT&CK Techniques | |

---

## 2. Affected Assets

| Asset | Type | Owner / Department | Criticality |
|-------|------|--------------------|-------------|
| | Workstation / Server / Cloud / Account | | Critical / High / Medium / Low |

---

## 3. Timeline of Events

| Time (UTC) | Event | Source |
|-----------|-------|--------|
| | Initial alert triggered | SIEM |
| | Alert assigned to analyst | Ticketing system |
| | | |
| | Containment action taken | |
| | Incident closed or escalated | |

---

## 4. Technical Findings

### 4.1 Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| IP Address | | |
| Domain | | |
| File Hash (SHA256) | | |
| File Name | | |
| Registry Key | | |
| URL (defanged) | | |

### 4.2 Investigation Summary

Describe what you found during investigation. Include query results, process tree analysis, network connections, and other relevant technical details.

---

## 5. Root Cause

What was the initial access vector or root cause?

Example: "User opened a macro-enabled attachment from a phishing email. The macro launched PowerShell which downloaded a remote access tool."

---

## 6. Impact Assessment

| Question | Answer |
|----------|--------|
| Was any data accessed or exfiltrated? | Yes / No / Unknown |
| If yes, what data (type and volume)? | |
| Was any system compromised? | Yes / No |
| If yes, which systems? | |
| Was any service disrupted? | Yes / No |
| GDPR notification required? | Yes / No / Under assessment |
| Estimated business impact | None / Low / Medium / High |

---

## 7. Containment Actions Taken

| Action | Taken By | Time (UTC) |
|--------|----------|-----------|
| | | |

---

## 8. Escalation

- Escalated: Yes / No
- If yes, escalated to:
- Time of escalation (UTC):
- Reason for escalation:

---

## 9. Final Disposition

| Field | Value |
|-------|-------|
| Classification | True Positive / False Positive / Benign Positive |
| Closed by | |
| Closed at (UTC) | |
| Total investigation time | |

---

## 10. Recommendations

List any recommendations to prevent recurrence or improve detection:

1.
2.
3.
