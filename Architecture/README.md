# Architecture

This folder contains the network architecture of the SOC lab.

The lab consists of three virtual machines:

- Kali Linux (Attacker)
- Windows 10 (Victim)
- Ubuntu Server (Wazuh)

The attacker generates malicious activity against the Windows endpoint.

The Windows endpoint records events using Sysmon and forwards them through the Wazuh Agent to the Wazuh Manager for analysis.

Alerts are then investigated from the Wazuh Dashboard.
