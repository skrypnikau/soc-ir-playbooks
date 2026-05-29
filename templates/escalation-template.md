# Escalation Message Template

Use this template when escalating an incident to Tier-2, the IR team, or management. Fill in all sections. Send via your agreed escalation channel (Slack #ir-escalations, PagerDuty, email to ir-team@company.com — adapt to your organisation).

---

## Escalation Message Format

**SUBJECT:** [ESCALATION] Incident #[ID] - [Severity] - [Brief Description] - [Date]

**From:** [Your name] - SOC Tier-1
**To:** [Tier-2 analyst on-call / IR team lead / Manager]
**Time (UTC):** [timestamp]

---

**INCIDENT SUMMARY**

Incident ID: [ID]
Severity: [Critical / High]
Type: [Phishing / Brute Force / Lateral Movement / Malware / Data Exfiltration]
Status: Active — requires Tier-2 response

---

**WHAT HAPPENED**

[2-4 sentence summary of what was detected and confirmed. Be concise but include the key facts.]

Example: "At 14:32 UTC, a High severity alert fired for lateral movement from host WORKSTATION-42 to three additional hosts. Investigation confirmed the attacker used Pass-the-Hash to authenticate as service account SVCADMIN across hosts WEB-01, APP-02, and FILE-03. No domain controller access detected yet but movement toward DC-01 is suspected."

---

**AFFECTED ASSETS**

- [List each affected host and any compromised accounts]

---

**KEY INDICATORS OF COMPROMISE**

- IP address:
- File hash:
- Domain:
- Compromised account:

---

**ACTIONS ALREADY TAKEN BY TIER-1**

- [List what has already been done with timestamps]
- Example: "Host WORKSTATION-42 isolated via EDR at 14:45 UTC"
- Example: "SVCADMIN account disabled in Active Directory at 14:47 UTC"

---

**REASON FOR ESCALATION**

[Explain specifically why this cannot be handled at Tier-1. Choose from the examples below or write your own.]

- Compromise spans multiple hosts and requires IR team coordination
- Suspected domain admin compromise requiring domain-level response
- GDPR notification assessment required — DPO needs to be looped in
- Active malware on endpoint requiring forensic acquisition and deeper analysis
- Customer or partner data may have been exfiltrated — management notification required
- Ransomware indicators detected — crisis response process to be initiated

---

**IMMEDIATE ACTIONS NEEDED FROM TIER-2**

1. [Be specific. Example: "Confirm whether domain controller DC-01 shows any logon events from SVCADMIN in the last 4 hours"]
2. [Example: "Approve full network isolation of the workload segment"]
3. [Example: "Take ownership of the incident and initiate the formal IR process"]

---

**INCIDENT TICKET / SIEM LINK**

[Link to the incident in your SIEM or ITSM ticketing system]

---

**ANALYST CONTACT**

Name: [Your name]
Direct contact during incident: [Phone / Slack handle]

---

## Notes on Escalation Etiquette

- Call the Tier-2 analyst directly after sending this message — do not rely on them seeing the message
- Escalate early when in doubt — it is better to over-escalate a false positive than to under-escalate a real incident
- Do not pause your investigation while waiting for Tier-2 to respond — keep documenting and contain where authorised
- If Tier-2 does not acknowledge within 15 minutes, escalate to the on-call manager
