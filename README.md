# SOC Incident Response Playbooks

![Focus](https://img.shields.io/badge/Focus-SOC%20Tier--1%20IR-red)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![Playbooks](https://img.shields.io/badge/Playbooks-5-blue)

A collection of Tier-1 SOC incident response playbooks covering the most common alert types a SOC analyst encounters. Each playbook maps to MITRE ATT&CK techniques, provides step-by-step triage procedures, containment guidance, escalation criteria, and a documentation template.

These playbooks were developed as part of self-study for SOC analyst roles and are designed to be practical and tool-agnostic — the triage logic applies whether you're working in Sentinel, Splunk, QRadar, or any other SIEM.

---

## How to Use These Playbooks

1. **Receive an alert** from your SIEM or ticketing system.
2. **Identify the alert type** — match it to one of the playbooks below.
3. **Follow the triage steps** in order. Each step includes the question you're trying to answer and how to find the answer.
4. **Apply the containment steps** if the incident is confirmed malicious.
5. **Use the escalation criteria** to decide whether to close, monitor, or escalate.
6. **Document** your findings using the template at the end of each playbook.

> These playbooks assume a Windows-centric environment with a SIEM that ingests Windows Security Events and endpoint telemetry (EDR/Sysmon). Adjust queries for your environment.

---

## Playbook Index

| # | Playbook | MITRE Techniques | Severity |
|---|----------|-----------------|---------|
| 01 | [Phishing Triage](playbooks/01-phishing-triage.md) | T1566.001, T1566.002, T1204 | Medium–High |
| 02 | [Brute Force Detection](playbooks/02-brute-force-detection.md) | T1110.001, T1110.003 | Medium |
| 03 | [Lateral Movement](playbooks/03-lateral-movement.md) | T1021.001, T1021.002, T1550.002 | High |
| 04 | [Malware Alert](playbooks/04-malware-alert.md) | T1059, T1055, T1547 | High–Critical |
| 05 | [Data Exfiltration Indicators](playbooks/05-data-exfiltration-indicators.md) | T1048, T1041, T1567 | High–Critical |

---

## MITRE ATT&CK Coverage

See [`mitre-mapping.md`](mitre-mapping.md) for the full technique-to-playbook mapping table.

**Tactics covered:**
- Initial Access (TA0001)
- Execution (TA0002)
- Persistence (TA0003)
- Lateral Movement (TA0008)
- Collection (TA0009)
- Exfiltration (TA0010)
- Command and Control (TA0011)

---

## Templates

| Template | Purpose |
|----------|---------|
| [`templates/incident-report-template.md`](templates/incident-report-template.md) | Structured incident report to fill out after triage |
| [`templates/escalation-template.md`](templates/escalation-template.md) | Pre-formatted escalation message to Tier-2 / IR team |

---

## Escalation Decision Guide

```
Alert received
      │
      ▼
Is there evidence of successful compromise?
  YES ──► Is there evidence of data access/exfiltration or lateral movement?
              YES ──► CRITICAL — Escalate immediately + notify manager
              NO  ──► HIGH — Contain, document, escalate to Tier-2
  NO  ──► Is the alert a true positive (attack attempted, failed)?
              YES ──► Document, apply watchlist/block, close or monitor
              NO  ──► Investigate further — may be false positive or tuning needed
```

---

## Author

**Yauheni Skrypnikau** - Career-changer building blue-team / SOC skills  
*   **LinkedIn:** [linkedin.com/in/skrypnikau](https://www.linkedin.com/in/skrypnikau)
*   **GitHub:** [github.com/skrypnikau](https://github.com/skrypnikau)
