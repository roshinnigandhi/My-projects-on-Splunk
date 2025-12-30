# SSH Brute-Force Detection & Analysis – Splunk

## 1. Project Overview
This project simulates an end-to-end SOC workflow for detecting and investigating
SSH brute-force attacks using Splunk. It focuses on visibility, detection, investigation,
and response rather than a single alert rule.

## 2. Threat Context & Use Case
SSH is a common attack surface in enterprise environments. Brute-force login attempts
can indicate credential attacks, misconfigurations, or unauthorized access attempts.
This project addresses how SOC analysts monitor and respond to such activity.

## 3. Data Source & Log Ingestion
- SSH authentication logs (sample dataset)
- Logs ingested into Splunk using manual upload
- Events include authentication status, usernames, source IPs, and timestamps

## 4. Field Extraction & Data Normalization
Key fields extracted and used for analysis:
- src_ip – Source IP address
- auth_status – Authentication result (success / failure / undetermined)
- _time – Event timestamp

This step ensures logs are usable for detection and correlation.

## 5. Baseline Analysis & Visibility
Before detecting attacks, baseline analysis was performed to understand:
- Total authentication attempts
- Ratio of successful vs failed logins
- Top source IP

This establishes normal vs abnormal behavior.

## 6. Detection Engineering – Brute-Force Identification
Brute-force attempts are detected using a time-based threshold:
- More than 20 failed login attempts
- From the same source IP
- Within a 5-minute window

### Core SPL Example

```spl
index=main sourcetype=ssh auth_status=failure
| bin _time span=5m
| stats count AS failed_attempts by src_ip, _time
| where failed_attempts > 20
```

## 7. Investigation & Compromise Validation
After brute-force activity is detected:
- Successful login events are analyzed
- Correlation is performed to determine if brute-force led to account compromise
- Source IPs and targeted accounts are reviewed

## 8. SOC Response Actions
Based on investigation findings:
- Suspicious IPs are escalated
- Malicious sources can be blocked via firewall / IDS
- Affected user accounts are reviewed

## 9. Prevention & Hardening Recommendations
To reduce future risk:
- Enable MFA for SSH access
- Disable root login
- Implement fail2ban or similar controls

## 10. Dashboard & Visualizations
SOC-style dashboards were created to provide:
- Authentication trends
- Brute-force detection visibility
- Source IP activity overview

## 11. Full Project Report

📄 [SSH Brute-Force Detection – Full Project Report](SSH_Brute_Force_Detection_Report.pdf)


