# MITRE ATT&CK Technique Mapping

This table maps each playbook to the MITRE ATT&CK techniques it covers. Use this as a quick reference to identify which playbook to use when an alert maps to a specific technique.

---

## Technique to Playbook Index

| MITRE Technique ID | Technique Name | Tactic | Playbook |
|-------------------|---------------|--------|---------|
| T1566.001 | Spearphishing Attachment | Initial Access | [01 - Phishing Triage](playbooks/01-phishing-triage.md) |
| T1566.002 | Spearphishing Link | Initial Access | [01 - Phishing Triage](playbooks/01-phishing-triage.md) |
| T1204.001 | Malicious Link | Execution | [01 - Phishing Triage](playbooks/01-phishing-triage.md) |
| T1204.002 | Malicious File | Execution | [01 - Phishing Triage](playbooks/01-phishing-triage.md) |
| T1110.001 | Brute Force: Password Guessing | Credential Access | [02 - Brute Force Detection](playbooks/02-brute-force-detection.md) |
| T1110.003 | Brute Force: Password Spraying | Credential Access | [02 - Brute Force Detection](playbooks/02-brute-force-detection.md) |
| T1021.001 | Remote Services: RDP | Lateral Movement | [03 - Lateral Movement](playbooks/03-lateral-movement.md) |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | Lateral Movement | [03 - Lateral Movement](playbooks/03-lateral-movement.md) |
| T1021.006 | Remote Services: Windows Remote Management | Lateral Movement | [03 - Lateral Movement](playbooks/03-lateral-movement.md) |
| T1550.002 | Pass the Hash | Lateral Movement | [03 - Lateral Movement](playbooks/03-lateral-movement.md) |
| T1550.003 | Pass the Ticket | Lateral Movement | [03 - Lateral Movement](playbooks/03-lateral-movement.md) |
| T1059.001 | PowerShell | Execution | [04 - Malware Alert](playbooks/04-malware-alert.md) |
| T1059.003 | Windows Command Shell | Execution | [04 - Malware Alert](playbooks/04-malware-alert.md) |
| T1055 | Process Injection | Defence Evasion | [04 - Malware Alert](playbooks/04-malware-alert.md) |
| T1547.001 | Registry Run Keys | Persistence | [04 - Malware Alert](playbooks/04-malware-alert.md) |
| T1053.005 | Scheduled Task | Persistence | [04 - Malware Alert](playbooks/04-malware-alert.md) |
| T1071 | Application Layer Protocol | C2 | [04 - Malware Alert](playbooks/04-malware-alert.md) |
| T1003.001 | LSASS Memory | Credential Access | [04 - Malware Alert](playbooks/04-malware-alert.md) |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | [05 - Data Exfiltration](playbooks/05-data-exfiltration-indicators.md) |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | [05 - Data Exfiltration](playbooks/05-data-exfiltration-indicators.md) |
| T1567.002 | Exfiltration to Cloud Storage | Exfiltration | [05 - Data Exfiltration](playbooks/05-data-exfiltration-indicators.md) |
| T1020 | Automated Exfiltration | Exfiltration | [05 - Data Exfiltration](playbooks/05-data-exfiltration-indicators.md) |

---

## Tactic Coverage Summary

| Tactic | Techniques Covered | Playbooks |
|--------|------------------|---------|
| Initial Access (TA0001) | T1566.001, T1566.002 | Phishing Triage |
| Execution (TA0002) | T1204.001, T1204.002, T1059.001, T1059.003 | Phishing, Malware |
| Persistence (TA0003) | T1547.001, T1053.005 | Malware Alert |
| Credential Access (TA0006) | T1110.001, T1110.003, T1003.001 | Brute Force, Malware |
| Defence Evasion (TA0005) | T1055 | Malware Alert |
| Lateral Movement (TA0008) | T1021.001, T1021.002, T1021.006, T1550.002, T1550.003 | Lateral Movement |
| Command and Control (TA0011) | T1071 | Malware Alert |
| Exfiltration (TA0010) | T1048, T1041, T1567.002, T1020 | Data Exfiltration |

---

## Gaps and Future Playbooks

High-priority techniques not yet covered by a playbook in this repository:

| Technique | Tactic | Priority |
|-----------|--------|---------|
| T1078 - Valid Accounts | Initial Access / Persistence | High |
| T1190 - Exploit Public-Facing Application | Initial Access | High |
| T1486 - Data Encrypted for Impact (Ransomware) | Impact | Critical |
| T1070.001 - Clear Windows Event Logs | Defence Evasion | Medium |
| T1562.001 - Disable or Modify Tools | Defence Evasion | Medium |
