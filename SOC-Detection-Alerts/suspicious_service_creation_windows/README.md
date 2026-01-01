# Windows Suspicious Service Creation Detection

## Objective
Detect the creation of new Windows services that may indicate malicious persistence or privilege abuse on a Windows endpoint.

## Why This Alert Matters
Attackers frequently create or modify Windows services to establish persistence or execute malicious binaries with elevated privileges. Monitoring service creation events helps detect post-exploitation activity early in the attack lifecycle.

## MITRE ATT&CK Mapping
- TA0003 – Persistence
- TA0004 – Privilege Escalation
- T1543.003 – Create or Modify System Process: Windows Service

## Log Sources
- Windows System Event Log
- Event ID 7045 (Service Installed)

## Detection Logic (High-Level)
This detection monitors Windows System logs for the creation of new services. When a service installation event is observed, relevant service metadata such as service name, executable path, and account context is extracted for investigation.

## Trigger Condition
- **Alert type:** Scheduled
- **Time range:** Last 1 minute
- **Trigger when:** Number of results > 0
- **Trigger mode:** Once
- **Throttle:** 60 seconds

**Reasoning:**  
Service creation is a low-frequency, high-risk activity. Triggering on any occurrence ensures immediate visibility while throttling prevents duplicate alerts during repeated installations.

## Attack Simulation
The alert was validated by manually creating a Windows service on the endpoint to simulate malicious persistence behavior.

This action generated Event ID 7045 in the Windows System logs, which was successfully ingested and detected by Splunk.

## Validation
- The alert triggered immediately upon service creation.
- SPL results confirmed the service name and executable path.
- Raw event logs were reviewed to validate legitimacy.

Relevant evidence is available in the `screenshots/` directory.

## False Positive Considerations
- Legitimate software installations
- Administrative maintenance activities
- Endpoint management or monitoring tools

## SOC Response Actions
1. Review the service name and executable path
2. Verify whether the service is expected or authorized
3. Check the binary reputation and file location
4. Identify the user or process responsible for creation
5. Disable and remove the service if malicious
