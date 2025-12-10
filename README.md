# Threat Hunting Lab: “IT Support” Recon Simulation

## Scenario

What appeared to be a routine support request was actually system recon: probing, collecting information, and leaving persistence mechanisms behind. Then, right as the activity became suspicious, a conveniently placed “explanation” file appeared. This wasn’t support work — it was misdirection.

**INTEL:**
  - Multiple machines were spawning processes from `Downloads` folders during early October.
  - Shared file traits: similar executables, naming patterns, and keywords _desk, help, support, tool_.
  - Intern-operated machines were affected.

---

## Executive Summary

What looked like routine IT support on the intern workstation gab-intern-vm was actually a series of suspicious activities. Instead of simply helping, the session involved probing the system, collecting information, testing network access, and setting up ways to maintain access.

At each step, actions were structured and sequential: initial script execution, host and session checks, storage and privilege review, outbound connectivity testing, and consolidation of files. Finally, a staged “chat log” was placed to create a false explanation for the behavior.

The activity was deliberate and coordinated, not standard support. This report lays out the timeline, the artifacts left behind, and the key indicators that distinguish legitimate support from staged reconnaissance.

---

## 📅 Timeline of Events

| **Flag** | **Timestamp** | **Stage** | **Event / Artifact** |
|----------|---------------------|-----------|-----------------------|
| **Flag 1** | 12:22:27 | Initial Execution | `SupportTool.ps1` executed from Downloads with `-ExecutionPolicy Bypass` |
| **Flag 2** | 12:34:59 | Defense Deception | staged security changes file created → `DefenderTamperArtifact.lnk` |
| **Flag 3** | 12:50 | Data Probe | Clipboard accessed via Powershell → `Get-Clipboard` |
| **Flag 4** | 12:51:44 | Session Recon | `qwinsta` executed to enumerate sessions |
| **Flag 5** | 12:51:18 | Storage Mapping | storage assessment → `wmic logicaldisk get name,freespace,size` |
| **Flag 6** | 12:51:44 | Presence Check | `cmd.exe /c query session` triggered from `RuntimeBroker.exe` |
| **Flag 7** | 12:50-12:52 | Interactive Session | Repeated session queries (same InitiatingProcessUniqueId) |
| **Flag 8** | 12:51:57 | Runtime Inventory | `tasklist.exe` executed |
| **Flag 9** | 12:52-12:54 | Privilege Recon | `whoami /groups` and `/priv` |
| **Flag 10** | 12:58:16 | Egress Check | First outbound request → `www.msftconnecttest.com` |
| **Flag 11** | 12:58:17 | Staging | `ReconArtifacts.zip` created in `C:\Users\Public\` |
| **Flag 12** | 13:00:40 | Exfil Attempt | outbound HTTPS to `httpbin.org` 100.29.147.161 |
| **Flag 13** | 13:01 | Persistence | Scheduled task `SupportToolUpdater` created |
| **Flag 14** | 13:02 | Fallback Persistence | Autorun registry value `RemoteAssistUpdater` added |
| **Flag 15** | 13:02:41 | Misdirection | Narrative artifact created → `SupportChat_log.lnk` |

---

## Starting Point

**Objective**
Identify where to start hunting with the above intel given.

Query:

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01)..datetime(2025-10-15))
| where FolderPath contains "download"
| where FileName contains "support"
   or FileName contains "tool"
   or FileName matches regex "desk(!top)"
   or FileName contains "help"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by TimeGenerated desc
```

| |
|---|
| <img src="https://github.com/user-attachments/assets/8a94ba72-f499-4b41-941b-b75f903a23f0" width="100%"> |

**Findings**
- `.ps1` file executed from the `Downloads` folder
- filename `supporttool` is inline with keywords from intel
- October 9th date is within investigation window

**Analysis**
- Downloads is not a trusted folder as files here are unvetted.
- Threat actors often execute from Downloads since it requires no special permissions
- Script was given a Support-themed title

---

# Flag Walkthrough

### Flag 1 – Initial Execution Detection

**Objective** 
Detect the earliest anomalous execution representing an entry point.

Query:

```kql
let T1 = todatetime('2025-10-09T12:22:00');
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains ".ps1"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName, ProcessCommandLine
| where TimeGenerated between (T1 -5m .. T1 + 5m)
| order by TimeGenerated desc
```
<kbd>
<img width="1294" alt="image" src="https://github.com/user-attachments/assets/8993ee49-ee47-435d-b560-89fff8755430" />
</kbd>

| |
|---|
| <img src="https://github.com/user-attachments/assets/8993ee49-ee47-435d-b560-89fff8755430" width="100%"> |

**Findings**
- The `supporttool.ps1` file was run with the `-ExecutionPolicy` parameter

**Analysis**
- `-ExecutionPolicy` Bypass allows PowerShell to execute scripts without restrictions, warnings, or prompts
- Commonly leveraged in attacks to run malicious .ps1 files

**Flag Answer**: -ExecutionPolicy

---

### Flag 2 – Defense Disabling

**Objective** 
Identify simulated or staged security posture changes.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where TimeGenerated between (T1..T2)
| where DeviceName == "gab-intern-vm"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by TimeGenerated desc
```
<kbd>
<img width="1336" height="370" alt="image" src="https://github.com/user-attachments/assets/d934db1c-fbcc-46b5-87d2-ba30ce997600" />
</kbd>

**Findings**
- User created a shortcut to file `DefenderTamperArtifact.lnk`
- initiatingprocess is `Explorer.exe`, signifying file was **manually accessed**

**Analysis**
- The artifact only represents intent to indicate defense tampering
- Actual configuration changes may not have occurred
- The naming convention is overly descriptive, suggesting it's likely created to draw attention rather than perform a real function

**Flag Answer**: DefenderTamperArtifact.lnk

---

### Flag 3 – Quick Data Probe

**Objective**
Spot opportunistic checks for sensitive content.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where TimeGenerated between (T1 .. T2)
| where DeviceName == "gab-intern-vm"
| where FileName contains "clip"
   or InitiatingProcessCommandLine contains "clip" 
| order by TimeGenerated desc
```
<kbd>
<img width="1443" height="331" alt="image" src="https://github.com/user-attachments/assets/81a8e587-03de-4180-aee6-57ca267584d2" />
</kbd>

**Findings**
- User executed PowerShell command with `Get-Clipboard`

**Analysis**
- Malicious actors probe clipboards hoping to find sensitive information, such as passwords. 
- Extremely short-lived reconnaissance
- Clipboard enumeration is uncommon in legitimate support activity
- Additional commands, such as `try { … } catch { }`, are also present to suppress errors and discard outputs, reducing detection opportunities.

**Flag Answer**: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

---

### Flag 4 – Host Context Recon

**Objective**
Find activity that gathers basic host and user context to inform follow-up actions.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T2)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
| order by TimeGenerated desc
```
<kbd>
<img width="853" height="340" alt="image" src="https://github.com/user-attachments/assets/f9b2f8d3-a8d1-4d04-b919-a565c9c8b10d" />
</kbd>

**Findings**
-

**Analysis**
- qwinsta.exe enumerates logged-in users and session info; standard recon technique.
- qwinsta is a Windows command-line tool that lists active user sessions on a machine or remote server.

Shows session IDs, usernames, session states (active, disconnected), and types (console, RDP).

Often used in reconnaissance to see who is logged in and which sessions are active.

In attacks, it helps an actor determine if a user is present or plan lateral movement.

**Flag Answer (Last Recon Attempt Timestamp)**: 2025-10-09T12:51:44.3425653Z

---

### Flag 5 – Storage Surface Mapping

Objective: Detect enumeration of local/network storage.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T2)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "wmic"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
| order by TimeGenerated desc
```
<kbd>
<img width="971" height="271" alt="image" src="https://github.com/user-attachments/assets/42b518c1-3c6b-4c99-b3b7-f89abeb18866" />
</kbd>

Analysis:
Enumeration identifies data locations for later collection.

Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size

---

### Flag 6 – Connectivity & Name Resolution Check

Objective: Identify network reachability and DNS queries.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where ProcessCommandLine contains "Session"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<kbd>
<img width="1015" height="293" alt="image" src="https://github.com/user-attachments/assets/7b54a8ba-c195-4b72-9b56-33ce6ea9aad6" />
</kbd>

Analysis:
RuntimeBroker initiated cmd.exe /c query session to check interactive sessions — reconnaissance.

Answer: RuntimeBroker.exe

---

### Flag 7 – Interactive Session Discovery

Objective: Detect enumeration of active user sessions.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where ProcessCommandLine contains "/c"
| project TimeGenerated, InitiatingProcessUniqueId, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc
```

<kbd>
<img width="1309" height="547" alt="image" src="https://github.com/user-attachments/assets/af8d5b17-c6a5-4d7f-958d-eaccba5a585a" />
</kbd>

Analysis:
Child processes share the same MDE UniqueId, allowing correlation even with different PIDs.

Answer (Unique ID of Initiating Process): 2533274790397065

---

### Flag 8 – Runtime Application Inventory

Objective: Identify activity that enumerates running processes or services on the host.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "list" 
   or InitiatingProcessCommandLine contains "list"
| where TimeGenerated between (T1 .. T2)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<kbd>
<img width="702" height="186" alt="image" src="https://github.com/user-attachments/assets/87a06be4-a270-4fb0-8312-6ac54abaf526" />
</kbd>

Analysis:
tasklist.exe enumerates all running processes — standard recon.

Answer (Process FileName): tasklist.exe

---

### Flag 9 – Privilege Surface Check

Objective: Identify attempts to enumerate the current user’s privilege level, group membership, and available security tokens.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "who" 
   or InitiatingProcessCommandLine contains "who"
| where TimeGenerated between (T1 .. T2)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

<kbd>
<img width="1468" height="562" alt="image" src="https://github.com/user-attachments/assets/00ffbc98-93e4-46c4-8acf-debfa735ae83" />
</kbd>

Analysis:
Privilege and group membership enumeration guides attack strategy.

Answer (Timestamp of first attempt): 2025-10-09T12:52:14.3135459Z

---

### Flag 10 – Proof-of-Access & Egress Validation

Objective:Identify network activity that demonstrates both the ability to reach external destinations and the intent to validate outbound communication pathways.

Queries:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where FileName contains "support" 
| order by TimeGenerated asc
| project TimeGenerated, ActionType, DeviceName, FileName
```

<kbd>
<img width="645" height="190" alt="image" src="https://github.com/user-attachments/assets/37a83a24-f754-4cd2-9207-8262b3599edf" />
</kbd>

```kql
let T1 = datetime(2025-10-09T12:58:00);
DeviceNetworkEvents
| where TimeGenerated between (T1 - 5m .. T1 + 5m)
| where DeviceName == "gab-intern-vm"
| where ActionType contains "success"
| where RemoteUrl != ""
| order by TimeGenerated asc
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
```

<kbd>
<img width="706" height="280" alt="image" src="https://github.com/user-attachments/assets/a501cc0e-111b-4739-8a12-b10c515907e5" />
</kbd>

Analysis:
The first contact with an external URL validates outbound connectivity; the files created afterward served as proof-of-access.

Answer (First Outbound Destination): www.msftconnecttest.com

---

### Flag 11 – Bundling / Staging Artifacts

Objective: Identify actions that consolidate reconnaissance outputs or collected artifacts into a single location or compressed package.

Query:
```kql
let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where FileName contains ".zip" 
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType
```

<kbd>
<img width="652" height="235" alt="image" src="https://github.com/user-attachments/assets/3707b9c7-abeb-495c-a38a-ed03a7c6aeba" />
</kbd>

Analysis:
Artifacts consolidated into a ZIP for potential exfiltration.

Answer (File Path): C:\Users\Public\ReconArtifacts.zip

---

### Flag 12 – Outbound Transfer Attempt (Simulated)

Objective: Identify any network activity indicating an attempt to move staged data off the host.

Queries:
```kql
let T1 = datetime(2025-10-09T12:30:00);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T1 + 2h)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "chat" or InitiatingProcessCommandLine contains "chat"
| order by TimeGenerated desc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine
```

<kbd>
<img width="1600" height="118" alt="image" src="https://github.com/user-attachments/assets/d731234c-d49d-44d3-8c4f-712c425c90f8" />
</kbd>

```kql
let T1 = datetime(2025-10-09T13:00:00);
DeviceNetworkEvents
| where TimeGenerated between (T1 .. T1 + 10m)
| where DeviceName == "gab-intern-vm"
| where RemoteIP != ""
| order by TimeGenerated asc
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessIntegrityLevel, LocalIP, LocalPort, Protocol, RemoteIP, RemoteIPType, RemotePort, RemoteUrl, ReportId
```

<kbd>
<img width="700" height="507" alt="image" src="https://github.com/user-attachments/assets/5920bb03-d5be-465f-87d4-b8fdebbaab0d" />
</kbd>

Analysis:
Outbound HTTPS to httpbin.org via PowerShell demonstrates simulated exfiltration attempt.

Answer (IP of last unusual outbound connection): 100.29.147.161

---

### Flag 13 – Scheduled Re-Execution Persistence

Objective: Identify mechanisms that ensure the attacker’s tooling will automatically run again after a reboot or user sign-in.

Query:
```kql
let T1 = datetime(2025-10-09);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T1 + 1d)
| where ProcessCommandLine contains "supporttool"
```

<kbd>
<img width="1600" height="282" alt="image" src="https://github.com/user-attachments/assets/d9cf7cc1-0e5d-4e62-a5fd-50dd0e99f4f3" />
</kbd>

Analysis:
Scheduled task ensures tooling runs on user logon.

Answer (Task Name): SupportToolUpdater

---

### Flag 14 – Autorun Fallback Persistence

Objective: Identify lightweight persistence mechanisms created under the user context, specifically autorun entries in the registry or startup directory.

Query:
```kql
let T1 = datetime(2025-10-09);
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T1 + 1d)
| where ActionType contains "RegistryValueSet" or ActionType contains "RegistryValueModified"
```

<kbd>
<img width="1423" height="856" alt="image" src="https://github.com/user-attachments/assets/2eb76260-2592-4806-b656-6d6cf58c31c2" />
</kbd>

Analysis:
Fallback autorun entry increases persistence resilience.

Answer (Registry Value Name): RemoteAssistUpdater

---

### Flag 15 – Planted Narrative / Cover Artifact

Objective: Identify any artifacts deliberately created to justify, disguise, or mislead investigators regarding the nature of the suspicious activity. 

Query:
```kql
let T1 = datetime(2025-10-09T12:00:00);
let T2 = datetime(2025-10-09T14:00:00);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where FileName contains "support"
| order by TimeGenerated desc
```

<kbd>
<img width="1600" height="170" alt="image" src="https://github.com/user-attachments/assets/a8fc6831-bf4f-4317-9eb6-af3853a4469a" />
</kbd>

Analysis:
A user-facing file mimicking a helpdesk chat to justify suspicious activity.

Answer (Artifact File Name): SupportChat_log.lnk
