# Linux User Added to sudo Group Detection

## Objective
Detect when a user account is added to the `sudo` group on a Linux system, which may indicate privilege escalation or unauthorized administrative access.

## Why This Alert Matters
Adding a user to the `sudo` group grants administrative privileges on Linux systems.

Attackers commonly escalate privileges by:

- Adding compromised accounts to the `sudo` group
- Modifying group memberships for persistence
- Elevating newly created accounts
- Establishing long-term privileged access

Monitoring changes to the `sudo` group is critical for detecting privilege escalation activity.

## MITRE ATT&CK Mapping
- **TA0004 – Privilege Escalation**
- **TA0003 – Persistence**
- **T1098 – Account Manipulation**
- **T1136.001 – Create Account: Local Account** (if chained with account creation)

## Log Sources
- **Linux System Logs**
  - `/var/log/auth.log`
  - `/var/log/syslog`
- Log patterns:
  - `usermod`
  - `sudo`

Relevant fields extracted:
- `actor_user`
- `target_user`
- `host`
- `_time`

## Detection Logic (High-Level)
This detection monitors Linux logs for commands that modify user group memberships, specifically when a user is added to the `sudo` group.

The detection:

1. Searches for log entries containing:
   - `usermod`
   - `sudo`
2. Extracts:
   - The user performing the action (`actor_user`)
   - The user being added to the group (`target_user`)
3. Displays relevant event details for investigation.

This activity may indicate legitimate administrative action or malicious privilege escalation.

## Trigger Condition
- **Alert type:** Scheduled  
- **Schedule:** Every 1 minute (`*/1 * * * *`)  
- **Time range:** Last 1 minute  
- **Trigger when:** Number of results > 0  
- **Trigger frequency:** Once  
- **Throttle:** 60 seconds  

**Reasoning:**  
Privilege escalation events are high-risk activities. Immediate detection ensures rapid response while throttling prevents duplicate alerts.

## Attack Simulation
The alert was validated by manually adding a user to the `sudo` group.

Commands used:

```bash
sudo usermod -aG sudo test4
groups test4
```

This generated log entries related to `usermod` and `sudo`, which were successfully ingested and detected by Splunk.

## Validation
- The alert triggered immediately after the group modification.
- SPL results confirmed:
  - Host system
  - Acting administrator
  - Target user added to `sudo`
- Group membership was verified using the `groups` command.

Evidence is available in the `Screenshots/` directory.

## False Positive Considerations
- Legitimate administrative privilege assignments
- System provisioning processes
- Onboarding of new administrators

Environment-specific tuning may include:
- Monitoring only outside approved maintenance windows
- Alerting only for non-approved user accounts

## SOC Response Actions
1. Verify whether the privilege assignment was authorized  
2. Confirm the change request or ticket reference  
3. Identify the administrator responsible  
4. Review recent login activity for the target user  
5. Check for suspicious commands executed post-escalation  
6. Remove unauthorized sudo access immediately  
7. Escalate to incident response if malicious behavior is suspected  
