# Multiple Failed SSH Login Attempts Detection

## Objective
Detect multiple failed SSH login attempts from the same source IP address, which may indicate brute-force or password spraying activity.

## Why This Alert Matters
Attackers frequently attempt to gain unauthorized access to Linux systems by performing brute-force attacks against SSH services.

Repeated failed login attempts may indicate:

- Credential brute-force attacks
- Password spraying attempts
- Automated attack tools targeting SSH
- Reconnaissance activity against exposed services

Early detection of repeated failed login attempts allows security teams to block malicious IP addresses before a successful compromise occurs.

## MITRE ATT&CK Mapping
- **TA0006 – Credential Access**
- **T1110 – Brute Force**

## Log Sources
- **Linux Authentication Logs**
  - `/var/log/auth.log` (Debian/Ubuntu)
  - `/var/log/secure` (RHEL/CentOS)
- Ingested into Splunk
- Log message pattern:
  - `Failed password for <user> from <src_ip>`

Relevant fields:
- `src_ip`
- `user`
- `fail_count`

## Detection Logic (High-Level)
This detection monitors SSH authentication logs for failed login attempts.

It performs the following steps:

1. Extracts username and source IP from failed login messages.
2. Counts the number of failed attempts grouped by:
   - Source IP
   - Username
3. Triggers when the number of failed attempts is greater than or equal to 3 within the defined time window.

This behavior may indicate brute-force activity targeting SSH services.
## Trigger Condition
- **Alert type:** Scheduled  
- **Schedule:** Every 1 minute (`*/1 * * * *`)  
- **Time range:** Last 1 minute  
- **Trigger when:** Number of results > 0  
- **Trigger frequency:** Once  
- **Throttle:** 60 seconds  

**Reasoning:**  
Multiple failed login attempts within a short time window may indicate brute-force activity. Triggering after a threshold of three attempts balances detection sensitivity with noise reduction.

## Attack Simulation
The alert was validated by repeatedly attempting to SSH into the local system using incorrect credentials.

Command used:

```bash
ssh test1@127.0.0.1
```

Multiple incorrect password attempts were entered consecutively, generating repeated `Failed password` log entries.

These events were ingested into Splunk and successfully detected by the alert when the threshold was met.

## Validation
- The alert triggered after multiple failed SSH login attempts.
- SPL results confirmed:
  - Source IP address
  - Target username
  - Total number of failed attempts
- Raw authentication logs were reviewed to verify log accuracy.

Evidence is available in the `Screenshots/` directory.

## False Positive Considerations
- Users mistyping passwords
- Automated configuration tools retrying authentication
- Monitoring systems testing credentials

Environment-specific tuning may include:
- Increasing threshold for production environments
- Excluding trusted internal IP addresses

## SOC Response Actions
1. Identify the source IP address of failed attempts  
2. Check if the IP is external or internal  
3. Determine whether the username exists on the system  
4. Block or firewall the source IP if malicious  
5. Monitor for successful login attempts from the same IP  
6. Enable account lockout policies if appropriate  
7. Escalate if brute-force activity persists  
