# My-projects-on-Splunk

## SOC & SIEM Projects — Splunk

This repository contains **hands-on SOC-focused SIEM projects** built using **Splunk**.  
Each project demonstrates **end-to-end security monitoring workflows**, including:

- Log ingestion & field normalization  
- SPL-based detection engineering  
- Dashboard creation for visibility  
- Investigation & incident response thinking  

The goal of this repository is to showcase **practical SOC analyst skills**, not just tool usage.

---

## Projects

### SSH Brute-Force Detection & Analysis
A SOC-style project focused on detecting, investigating, and responding to SSH brute-force attacks.

**Key Highlights**
- Analyzed SSH authentication logs to identify brute-force patterns
- Built SOC-style dashboards using Splunk SPL
- Implemented threshold-based detection  
  *(>20 failed attempts from a single IP within 5 minutes)*
- Correlated failed and successful logins to assess potential compromise
- Mapped detections to SOC response and prevention actions

 **Project Folder:**  
[`SSH-Bruteforce-Detection`](./SSH-Bruteforce-Detection)

---

## Skills Demonstrated
- SIEM Monitoring (Splunk)
- SPL Query Writing & Optimization
- Detection Engineering
- Incident Investigation & Validation
- SOC Documentation & Reporting

---

## Notes
- Each project folder contains its own detailed README, SPL queries, and supporting documentation.
- Projects are designed to reflect **real-world SOC workflows**, not just isolated alerts.

---

*More projects will be added as I continue building SOC detection and response labs.*

