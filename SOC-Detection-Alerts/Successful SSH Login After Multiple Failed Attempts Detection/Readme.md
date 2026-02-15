# Successful SSH Login After Multiple Failed Attempts Detection

## Objective
Detect successful SSH authentication events that occur after multiple failed login attempts, which may indicate a successful brute-force attack.

## Why This Alert Matters
Repeated failed SSH login attempts followed by a successful authentication strongly suggest credential brute-force activity.

This pattern may indicate:

- Password guessing attacks
- Credential stuffing
- Brute-force automation tools
- Compromised user accounts

Unlike isolated failed attempts, this detection identifies when an attacker successfully gains access after multiple authentication failures, making it a high-risk security event.

## MITRE ATT&CK Mapping
- **TA0006 – Credential Access**
- **TA0001 – Initial Access**
- **T1110 – Brute Force**

## Log Sources
- **Linux Authentication Logs**
  - `/var/log/auth.log` (Debian/Ubuntu)
  - `/var/log/secure` (RHEL/CentOS)
- Ingested into Splunk
- Log message patterns:
  - `Failed password`
  - `Accepted password`

Relevant fields:
- `ssh_user`
- `src_ip`
- `failed_count`
- `success_count`

## Detection Logic (High-Level)
This detection monitors SSH authentication logs for both failed and successful login events.

It performs the following steps:

1. Extracts username and source IP from authentication logs.
2. Counts the number of:
   - Failed login attempts
   - Successful login attempts
3. Triggers when:
   - Failed attempts are greater than or equal to 3
   - At least one successful login occurs

This pattern indicates that repeated password attempts eventually resulted in successful authentication.

## Trigger Condition
- **Alert type:** Scheduled  
- **Schedule:** Every 1 minute (`*/1 * * * *`)  
- **Time range:** Last 1 minute  
- **Trigger when:** Number of results > 0  
- **Trigger frequency:** Once  
- **Throttle:** 300 seconds  

**Reasoning:**  
A successful login after multiple failed attempts indicates a potential compromise. Throttling is increased to reduce duplicate alerts during ongoing attack activity.

## Attack Simulation
The alert was validated by performing multiple failed SSH login attempts followed by a successful login.

Command used:

```bash
ssh test1@127.0.0.1
```

Steps performed:
1. Entered incorrect passwords multiple times.
2. Entered the correct password on a subsequent attempt.
3. Observed successful SSH login.

This generated both failed and accepted password events in authentication logs, which were successfully detected by the alert.

## Validation
- The alert triggered after a successful login following multiple failed attempts.
- SPL results confirmed:
  - Username targeted
  - Source IP address
  - Number of failed attempts
  - Successful login event
- Raw authentication logs were reviewed to validate accuracy.

Evidence is available in the `Screenshots/` directory.

## False Positive Considerations
- Users mistyping passwords before successful login
- Automated configuration scripts retrying credentials
- Shared accounts with multiple users

Environment-specific tuning may include:
- Increasing the failed attempt threshold
- Filtering trusted internal IP addresses
- Monitoring external IP sources more strictly

## SOC Response Actions
1. Identify the source IP address of the login  
2. Determine whether the IP is internal or external  
3. Confirm whether the login was legitimate  
4. Reset credentials for the affected account if suspicious  
5. Check for additional malicious activity post-login  
6. Block malicious IP addresses at firewall level  
7. Escalate to incident response if compromise is confirmed 
