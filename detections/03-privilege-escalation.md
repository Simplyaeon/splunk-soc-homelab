# Detection: Privilege Escalation

## Overview

Detects modification of sensitive account/privilege files — `/etc/sudoers`,
`/etc/passwd`, `/etc/shadow` — which is how an attacker (or a legitimate admin)
grants themselves elevated or persistent access.

| Field | Value |
|---|---|
| Index | `linux_audit` |
| Sourcetype | `linux_audit` |
| Log source | `/var/log/audit/audit.log` |
| auditd keys | `sudoers_change`, `passwd_change`, `shadow_change` |

## Attack Simulation

```bash
sudo visudo               # triggers sudoers_change
sudo passwd testuser      # triggers passwd_change / shadow_change
```

## Detection Logic

**Hypothesis:** Any write to these three files outside of a known, planned
maintenance window is worth surfacing — the base rate of legitimate changes
is very low.

```spl
index=linux_audit sourcetype=linux_audit (key=sudoers_change OR key=passwd_change OR key=shadow_change)
| stats count by host, key, auid
```

**Trigger threshold:** Any result (count > 0).

## Alert Configuration

| Field | Value |
|---|---|
| Alert Type | Scheduled |
| Schedule | Every minute, search over Last 1 minute |
| Trigger when | Number of Results > 0 |
| Severity | High |
| Action | Add to Triggered Alerts |

## Screenshot

_[screenshots/alert_privilege_escalation.png]_

## Notes

- The `acct` field is blank in SYSCALL records for these events — use `auid`
  instead to identify the actor.
- `auid=4294967295` means no authenticated session (background/daemon
  activity) — safe to ignore when triaging.
