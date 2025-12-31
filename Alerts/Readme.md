# SOC Detection Alerts – Splunk SIEM Project

## Project Overview
This repository contains a collection of **custom security detection alerts** designed, implemented, and validated in a controlled **SOC lab environment** using **Splunk SIEM**.

The objective of this project is to demonstrate **hands-on detection engineering skills** — from identifying attack behavior, writing SPL queries, configuring alert logic, triggering real attacks, and validating detections with logs and evidence.

This is a **demo-focused SOC project**, built to reflect how alerts are created and handled in real-world Security Operations Centers (SOC).

---

## What This Project Demonstrates
- Practical SOC alert creation (not theoretical rules)
- Understanding of attacker behavior and log patterns
- Ability to simulate attacks and validate detections
- MITRE ATT&CK–aligned detection logic
- SOC-style alert documentation and response thinking

---

## Lab Architecture
- **SIEM**: Splunk
- **Endpoints**:
  - Linux (authentication, user & privilege events)
  - Windows (process execution, PowerShell, local users, services)
- **Log Sources**:
  - Linux auth logs
  - Windows Security logs
  - Process and PowerShell activity
- **Attack Simulation**:
  - Manual command execution
  - Privilege escalation actions
  - Authentication abuse scenarios

All alerts in this repository were **manually triggered and validated** using real logs generated in the lab.

---

## Detection Categories Covered

### Authentication
- SSL / SSH brute-force attempts  
- Successful login after multiple failures  

### Privilege Escalation
- New local user creation (Linux & Windows)  
- User added to privileged groups (sudo / administrators)  

### Execution
- Suspicious PowerShell execution  
- Abnormal parent–child process relationships  

### Persistence
- Service creation and startup (e.g., FTP service)  

Each alert includes:
- Detection objective  
- MITRE ATT&CK mapping  
- Log source details  
- SPL query  
- Trigger conditions  
- Attack simulation steps  
- Validation evidence  
- False-positive considerations  
- SOC-style response guidance  

---

## 📂 Repository Structure
SOC-Detection-Alerts/
│
├── README.md
│
├── lab-architecture/
│ └── diagrams and log flow visuals
│
├── alerts/
│ ├── authentication/
│ ├── privilege-escalation/
│ ├── execution/
│ └── persistence/
│
├── spl/
│ └── SPL queries used for alerts
│
├── screenshots/
│ └── Alert triggers and log evidence
│
└── mitigation-playbooks/
└── SOC response actions per alert


---

## 🧪 Alert Validation Methodology
Each alert was validated using the following approach:
1. Simulate attacker or suspicious activity on endpoint
2. Generate real logs (Linux / Windows)
3. Verify log ingestion into Splunk
4. Execute SPL query
5. Trigger alert based on defined thresholds
6. Capture alert and log evidence

No synthetic or mock data was used.

---

## SOC Mindset & Best Practices
- Alerts are tuned to reduce noise and false positives
- Throttling and trigger conditions are thoughtfully applied
- Alerts focus on **behavior**, not just single events
- Detection logic aligns with real SOC workflows

---

## Who This Project Is For
- SOC Analyst (Tier 1 / Tier 2) roles  
- Detection Engineering learning paths  
- Blue Team portfolios  
- Interview demonstration and walkthroughs  

---

## Future Enhancements
- Add more persistence and lateral movement detections  
- Improve alert tuning based on false-positive analysis  
- Correlate multiple alerts into incident-level detections  
- Add automated response playbooks  

---

## Author
**SOC Analyst | Blue Team | Detection Engineering Enthusiast**

This project reflects hands-on learning and continuous improvement in security monitoring and incident detection.

