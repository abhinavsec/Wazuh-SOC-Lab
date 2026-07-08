# Attack 03 – After-Hours Interactive Windows Login Detection

---

## Objective

The objective of this detection scenario was to design, implement, and validate custom Wazuh detection rules capable of identifying successful Windows interactive logins and generating high-priority alerts whenever authentication occurred outside approved business hours.

Unlike the previous attack simulations, this exercise focuses on **custom detection engineering** rather than attacker emulation. The goal was to improve SOC visibility by creating custom correlation rules for Windows authentication events and validating their effectiveness using real Windows Security logs.

---

## Detection Overview

This detection scenario demonstrates how Windows Security Event ID **4624** can be leveraged to identify successful interactive logins and how Wazuh can correlate those events using custom rules to detect potentially suspicious after-hours authentication activity.

Successful logins outside normal business hours are not inherently malicious; however, they are frequently investigated by SOC analysts because they may indicate:

- Compromised credentials
- Insider threats
- Unauthorized remote access
- Lateral movement
- Privilege abuse
- Abnormal user behavior

To improve detection capabilities, two custom Wazuh rules were created:

- **Rule ID 100100** – Detect successful interactive Windows logins.
- **Rule ID 100101** – Detect interactive Windows logins occurring outside approved business hours.

Both rules were implemented in the `local_rules.xml` file and validated through controlled authentication testing.

---

## Lab Environment

| Component | Details |
|------------|----------|
| Wazuh Manager | Ubuntu Server |
| Monitored Endpoint | Windows 10 |
| SIEM Platform | Wazuh 4.x |
| Endpoint Agent | Wazuh Agent |
| Log Source | Windows Security Logs |
| Event ID Monitored | 4624 |
| Rule File | `/var/ossec/etc/rules/local_rules.xml` |

---

## Time Configuration (UTC)

The after-hours detection rule was configured using **Coordinated Universal Time (UTC)** rather than the local system timezone.

Wazuh evaluates time-based rule conditions internally using UTC. Configuring the rule in UTC ensures consistent alert generation regardless of the geographic location of monitored systems or analysts and avoids discrepancies caused by daylight saving time or timezone differences.

For testing purposes, the organization's approved login window was converted from Indian Standard Time (IST) to UTC before implementing the rule.

| IST | UTC |
|-----|-----|
| 8:30 PM | 3:00 PM |
| 10:30 PM | 5:00 PM |

Any successful interactive login occurring outside the configured UTC business hours generated an after-hours login alert.

> 📸 **Screenshot:** `local_rules.xml` showing Rule IDs **100100** and **100101**.
