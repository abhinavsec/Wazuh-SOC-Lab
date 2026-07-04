# Lab Setup

## Objective

The purpose of this lab is to simulate real-world cyber attacks and investigate them using Wazuh from a SOC Analyst's perspective.

---

## Lab Topology

| Machine | Operating System | Purpose |
|----------|------------------|---------|
| Kali Linux | Kali Linux | Attacker |
| Windows 10 | Windows 10 | Victim Machine |
| Ubuntu Server | Ubuntu 22.04 | Wazuh Server |

---

## Software Installed

### Ubuntu Server

- Wazuh Manager
- Wazuh Indexer
- Wazuh Dashboard

### Windows 10

- Wazuh Agent
- Sysmon

### Kali Linux

- Hydra
- Nmap
- Other penetration testing tools

---

## Network Configuration

The lab uses Oracle VirtualBox with isolated networking to allow communication between the attacker, victim, and Wazuh server.

---

## Detection Workflow

Attacker
↓
Windows 10
↓
Sysmon
↓
Wazuh Agent
↓
Wazuh Manager
↓
Dashboard
↓
SOC Investigation
