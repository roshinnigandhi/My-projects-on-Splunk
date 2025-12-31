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

