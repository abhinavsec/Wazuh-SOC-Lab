# Attack 02 – SMB File Transfer and PowerShell Account Discovery

---

## Objective

The objective of this simulation was to demonstrate how an attacker can remotely access a Windows SMB share, transfer a PowerShell script to the target system, execute the script, and observe how Wazuh detects and correlates the resulting discovery activity.

This exercise demonstrates how endpoint telemetry collected through Sysmon and Windows Event Logs can be analyzed by Wazuh to detect post-exploitation discovery techniques commonly used by attackers after gaining initial access.

---

# Lab Environment

| Component | Details |
|----------|----------|
| Attacker | Kali Linux |
| Victim | Windows 10 |
| SIEM | Wazuh Manager |
| Endpoint Monitoring | Wazuh Agent + Sysmon |
| Attack Protocol | SMB (TCP/445) |
| Attack Tool | smbclient |
| Script Executed | test.ps1 |
| Command Executed | net user |

---

# Attack Flow

```
Kali Linux
      │
      │
      ├── Scan SMB Service (TCP 445)
      │
      ├── Authenticate to SMB Share
      │
      ├── Upload PowerShell Script
      │
      ├── Execute Script on Windows
      │
      ▼
Windows 10
      │
      ├── PowerShell launches net.exe
      │
      ├── Sysmon logs Process Creation
      │
      ├── Windows Event Logs Generated
      │
      ▼
Wazuh Agent
      │
      ▼
Wazuh Manager
      │
      ▼
Security Alerts Generated
```

---

# Attack Execution

The attack began by identifying that the Windows endpoint exposed the SMB service over TCP port 445.

A shared folder named **Project** was configured on the Windows 10 system and made accessible using valid user credentials.

The attacker authenticated to the SMB share using the Linux `smbclient` utility and successfully uploaded a PowerShell script named **test.ps1**.

The uploaded PowerShell script contained the following command:

```
net user
```

The script was then executed on the Windows endpoint using PowerShell.

Executing the script caused Windows to enumerate all local user accounts on the system.

The primary objective of this simulation was not to compromise the system but to generate realistic endpoint telemetry representing attacker discovery behavior.

---

# Detection

Sysmon successfully monitored the execution of the PowerShell script and generated Process Creation events.

Wazuh collected the generated Sysmon logs and correlated them with built-in detection rules.

The SIEM generated alerts indicating that account discovery activity had occurred through PowerShell execution.

The generated alerts included:

- Source endpoint
- Timestamp
- Executed command
- Parent process
- Process Image
- Process Hash
- Windows Event ID
- MITRE ATT&CK Mapping
- Rule ID
- Rule Level

The collected telemetry clearly demonstrated how Wazuh can identify attacker discovery behavior using endpoint monitoring.

---

# Evidence Collection

## Network Information

| Item | Value |
|------|-------|
| Source IP | 10.0.3.9 |
| Target IP | 10.0.3.11 |
| Protocol | SMB |
| Port | TCP/445 |

---

## Script Information

| Item | Value |
|------|-------|
| Uploaded File | test.ps1 |
| Executed Command | net user |
| Execution Method | Windows PowerShell |

---

## Detection Information

| Field | Value |
|-------|-------|
| Rule ID | 92031 |
| Rule Level | 3 |
| Rule Description | Discovery activity executed |
| MITRE Technique | T1087 – Account Discovery |
| Windows Event Channel | Microsoft-Windows-Sysmon/Operational |
| Sysmon Event ID | 1 |
| Process | net.exe |

---

| Field | Value |
|-------|-------|
| Rule ID | 92033 |
| Rule Level | 3 |
| Rule Description | Discovery activity spawned via PowerShell execution |
| MITRE Technique | T1059.001 – PowerShell |
| Windows Event Channel | Microsoft-Windows-Sysmon/Operational |
| Sysmon Event ID | 1 |
| Parent Process | powershell.exe |

---

# Analysis

Analysis of the collected telemetry confirmed that the attacker authenticated to the SMB share and successfully transferred a PowerShell script to the Windows endpoint.

Execution of the uploaded script resulted in PowerShell spawning the Windows utility **net.exe** to enumerate local user accounts.

Sysmon generated detailed process creation events containing:

- Process Name
- Parent Process
- Command Line
- Process Hashes
- User Context
- Process GUID
- Timestamp

Wazuh correlated these events and classified the activity as **Discovery** under the MITRE ATT&CK framework.

Although the executed command itself is legitimate Windows functionality, its execution through a remotely transferred PowerShell script is behavior frequently observed during attacker reconnaissance.

---

# Analyst Decision

## Classification

**True Positive**

---

## Severity

**Medium**

---

## Reason

The activity was intentionally generated inside a controlled SOC laboratory.

The observed behavior matches legitimate attacker discovery techniques used after gaining access to a compromised system.

The uploaded PowerShell script executed a Windows administrative command that enumerated local user accounts.

Sysmon successfully captured the process creation event, while Wazuh accurately detected and classified the activity using built-in detection rules.

---

## Recommended Response

- Investigate the source IP address.
- Verify whether the SMB authentication was authorized.
- Review PowerShell execution logs.
- Investigate any additional commands executed after account enumeration.
- Restrict SMB access where unnecessary.
- Enable PowerShell logging.
- Monitor for abnormal use of Windows administrative utilities.

---

# MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID |
|---------|-----------|--------------|
| Discovery | Account Discovery | T1087 |
| Execution | PowerShell | T1059.001 |

---

# Indicators of Compromise (IOCs)

- SMB authentication from remote host
- Remote file upload over SMB
- Execution of PowerShell
- Execution of net.exe
- Command executed:
  ```
  net user
  ```
- Sysmon Event ID 1
- Wazuh Rule ID 92031
- Wazuh Rule ID 92033

---

# Detection Rules

| Rule ID | Description | Level |
|---------|-------------|-------|
| 92031 | Discovery activity executed | 3 |
| 92033 | Discovery activity spawned via PowerShell execution | 3 |

---


# Mitigation

To reduce the likelihood of similar attacks:

- Restrict SMB access using firewall rules.
- Disable unused SMB shares.
- Apply the Principle of Least Privilege.
- Enable PowerShell Script Block Logging.
- Enable PowerShell Transcription Logging.
- Enable Sysmon with a comprehensive configuration.
- Continuously monitor Windows Event Logs.
- Monitor PowerShell execution activity.
- Detect abnormal execution of Windows administrative utilities.
- Generate alerts for remote file transfers followed by script execution.

---

# Lessons Learned

This exercise demonstrates that seemingly benign Windows utilities such as **net.exe** can become valuable indicators of attacker activity when executed through PowerShell after remote file transfer.

Combining Sysmon telemetry with Wazuh correlation provides analysts with detailed visibility into attacker behavior during the post-exploitation phase.

The investigation highlights the importance of monitoring process creation, command-line arguments, parent-child process relationships, and PowerShell activity when defending Windows environments.

---

# Conclusion

The simulated SMB file transfer and PowerShell execution attack successfully generated endpoint telemetry representative of attacker discovery activity.

Sysmon recorded detailed process creation events while Wazuh accurately detected, correlated, and classified the behavior using MITRE ATT&CK techniques.

This exercise demonstrates the effectiveness of centralized log collection and endpoint monitoring in identifying post-exploitation activity and supports the role of a SOC analyst in investigating suspicious behavior across Windows systems.
