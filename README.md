# Threat Hunting Lab: “IT Support” Recon Simulation

### **Report Information**
**Analyst:** Justin Soflin  
**Date Completed:** Nov. 29, 2025  <br>
**Environment Investigated:** Cyber Range at LOG(N)Pacific  <br>
**Host Investigated:** gab-intern-vm <br>
**User Context:** g4bri3lintern <br>
**Tools & Data Sources:** Microsoft Azure, Log Analytics workspaces, KQL (Kusto Query Language)<br>
**Scope:** Behavioral review, artifact analysis, persistence detection, and network egress validation  <br>

---

## Table of Contents

1. [Report Information](#report-information)
2. [Scenario](#scenario)
3. [Executive Summary](#executive-summary)
4. [Timeline of Events](#timeline-of-events)
5. [Initial Detection](#starting-point)
6. [Flag Walkthrough](#flag-walkthrough)
    - [Flag 1 – Initial Execution Detection](#flag-1--initial-execution-detection)
    - [Flag 2 – Defense Disabling](#flag-2--defense-disabling)
    - [Flag 3 – Quick Data Probe](#flag-3--quick-data-probe)
    - [Flag 4 – Host Context Recon](#flag-4--host-context-recon)
    - [Flag 5 – Storage Surface Mapping](#flag-5--storage-surface-mapping)
    - [Flag 6 – Connectivity & Name Resolution Check](#flag-6--connectivity--name-resolution-check)
    - [Flag 7 – Interactive Session Discovery](#flag-7--interactive-session-discovery)
    - [Flag 8 – Runtime Application Inventory](#flag-8--runtime-application-inventory)
    - [Flag 9 – Privilege Surface Check](#flag-9--privilege-surface-check)
    - [Flag 10 – Proof-of-Access & Egress Validation](#flag-10--proof-of-access--egress-validation)
    - [Flag 11 – Bundling--staging-artifacts](#flag-11--bundling--staging-artifacts)
    - [Flag 12 – Outbound Transfer Attempt-simulated](#flag-12--outbound-transfer-attempt-simulated)
    - [Flag 13 – Scheduled Re-Execution Persistence](#flag-13--scheduled-re-execution-persistence)
    - [Flag 14 – Autorun Fallback Persistence](#flag-14--autorun-fallback-persistence)
    - [Flag 15 – Planted Narrative--cover-artifact](#flag-15--planted-narrative--cover-artifact)
7. [Recommended Response Actions](#recommended-response-actions)
8. [MITRE ATT&CK Mappings](#mitre-attck-mappings)
9. [Conclusion](#conclusion)

---

## Scenario

What appeared to be a routine support request was actually system recon: probing, collecting information, and leaving persistence mechanisms behind. Then, right as the activity became suspicious, a conveniently placed “explanation” file appeared. This wasn’t support work — it was misdirection.

**INTEL**
  - Multiple machines were spawning processes from `Downloads` folders during _early October_.
  - Shared file traits: similar executables, naming patterns, and keywords _desk, help, support, tool_.
  - Intern-operated machines were affected.

---

## Executive Summary

The investigation into device 'gab-intern-vm` exposed numerous suspicious activities, all under the guise of routine IT support. User accomplished this by using support-themed naming conventions and relying on legitimate tools that won't typically raise red flags. The session involved probing the system, collecting information, testing network access, and setting up ways to maintain access.

At each step, actions were structured and sequential: 
   - Initial script execution
   - Host and session checks
   - Storage and privilege review
   - Outbound connectivity testing
   - Consolidation of files
   - Staged “chat log” to justify the behavior

Although no actual exfiltration took place, the activity was deliberate and coordinated, not standard support. This report lays out the timeline, the artifacts left behind, and the key indicators that distinguish legitimate support from staged reconnaissance.

---

## Timeline of Events

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

**Objective** <br>
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

<br>

| |
|---|
| <img src="https://github.com/user-attachments/assets/8a94ba72-f499-4b41-941b-b75f903a23f0" width="100%"> |

<br>

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

**Objective** <br>
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

| |
|---|
| <img src="https://github.com/user-attachments/assets/8993ee49-ee47-435d-b560-89fff8755430" width="100%"> |

<br>

**Findings**
- The `supporttool.ps1` file was run with the `-ExecutionPolicy` parameter

**Analysis**
- `-ExecutionPolicy` Bypass allows PowerShell to execute scripts without restrictions, warnings, or prompts
- Commonly leveraged in attacks to run malicious .ps1 files

**Flag Answer**: -ExecutionPolicy

---

### Flag 2 – Defense Disabling

**Objective** <br>
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

<br>

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

**Objective** <br>
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

<br>

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

**Objective** <br>
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
</kbd> <br>

**Findings**
- User executed the `qwinsta` command

**Analysis** 
- `qwinsta` is a Windows command-line tool that shows:
   - session IDs
   - usernames
   - session states (active, disconnected)
   - types (console, RDP)
- Often used in reconnaissance to see who is logged in and which sessions are active.
- In attacks, it helps an actor determine if a user is present or plan lateral movement.

**Flag Answer (Last Recon Attempt Timestamp)**: 2025-10-09T12:51:44.3425653Z

---

### Flag 5 – Storage Surface Mapping

**Objective** <br>
Detect enumeration of local/network storage.

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

<br>

**Findings**
- User executed a `WMIC` command

**Analysis**
- `wmic logicaldisk get name,freespace,size` → list all drives and show:
   - Drive letter (C:, D:, etc.)
   - Free space
   - Total size
- Why attackers use it
   -  Shows what storage exists on the machine
   - Where large data volumes might be
   - Which drives are worth scanning or exfiltrating

**Flag Answer**: "cmd.exe" /c wmic logicaldisk get name,freespace,size

---

### Flag 6 – Connectivity & Name Resolution Check

**Objective** <br>
Identify network reachability and DNS queries.

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

<br>

**Findings**
- User executed the `query session` command

**Analysis**
- `query session` is a Windows command that lists all Terminal Services / Remote Desktop sessions on the machine. It shows:
   - Username
   - Session name
   - Session ID
   - State (Active / Disconnected)
   - Idle time
   - Logon time

**Flag Answer**: RuntimeBroker.exe

---

### Flag 7 – Interactive Session Discovery

**Objective** <br>
Detect enumeration of active user sessions.

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

<br>

**Findings**
- User executed several session enumeration commands, such as `quser`, `net use`, `ipconfig`, and `whoami`

**Analysis**
- Child processes share the same _InitiatingProcessUniqueId_, allowing correlation even with different PIDs

**Flag Answer (Unique ID of Initiating Process)**: 2533274790397065

---

### Flag 8 – Runtime Application Inventory

**Objective** <br>
Identify activity that enumerates running processes or services on the host.

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

<br>

**Findings**
- User ran `tasklist /v` command

**Analysis**
- tasklist enumerates all running processes, essentially TaskManager in text view
- `/v` switch, or _verbose_ output, includes additional details to the tasklist command
- Attackers may be looking to:
   - Identify security tools running
   - Spot analysis tools or admin activity
   - Find high‑value processes to target
   - See which user accounts own which processes
- Low noise, low risk, high information

**Flag Answer (Process FileName)**: tasklist.exe 

---

### Flag 9 – Privilege Surface Check

**Objective** <br>
Identify attempts to enumerate the current user’s privilege level, group membership, and available security tokens.

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

<br>

**Findings**
- User ran `whoami` command with `/groups` switch

**Analysis**
- `whoami /groups` is a Windows command that lists all the groups the current user belongs to
- Shows access scope and privileges. Being part of certain groups (like Administrators or Domain Admins) gives elevated rights
- Malicious actors use it to see what permissions they already have and plan what they can do next
- Final flag for session enumeration

**Flag Answer (Timestamp of first attempt)**: 2025-10-09T12:52:14.3135459Z

---

### Flag 10 – Proof-of-Access & Egress Validation

**Objective** <br>
Identify network activity that demonstrates both the ability to reach external destinations and the intent to validate outbound communication pathways.

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

<br>

**Findings**
- User accessed the Microsoft connectivity check domain `www.msftconnecttest.com`
- Aligns with attempts to validate outbound internet communication rather than providing legitimate IT support

**Analysis**
- `msftconnecttest.com` is a legitimate domain used to verify internet connectivity
- Outbound requests to this domain may not trigger alerts or appear suspicious in network logs
- Executed from a user‑initiated PowerShell session
- Enabled actor to identify which outbound ports, domains, and protocols are permitted by the network

**Flag Answer (First Outbound Destination)**: www.msftconnecttest.com

---

### Flag 11 – Bundling / Staging Artifacts

**Objective** <br>
Identify actions that consolidate reconnaissance outputs or collected artifacts into a single location or compressed package.

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

<br>

**Findings**
- User created a .zip file conveniently named `ReconArtifacts.zip`

**Analysis**
- All previous reconnaissance is saved to a .zip file
- `C:\Users\Public\` helps the actor conceal their own user profile
- This folder path may appear normal in logs and not be heavily scrutinized
- Allows the actor to prepare data for later exfiltration or move artifacts between accounts

**Flag Answer (File Path)**: C:\Users\Public\ReconArtifacts.zip

---

### Flag 12 – Outbound Transfer Attempt (Simulated)

**Objective** <br>
- Identify any network activity indicating an attempt to move staged data off the host
- Succeeded or not, attempt is still proof of intent, and it reveals egress paths or block points

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

<br>

**Findings**
- User successfully connected to external IP `100.29.147.161`, `httpbin.org`, with PowerShell

**Analysis**
- `httpbin.org` is a public service that echoes HTTP requests
- Serves as an egress test by:
   - Verifying that outbound HTTP(S) traffic is allowed from the host
   - Confirming that firewalls, proxies, or egress filters do not block traffic
-  Doesn’t trigger alerts because the domain is well-known and non-malicious
-  Executing from PowerShell indicates deliberate operator behavior, not background system traffic
  
**Flag Answer (IP of last unusual outbound connection)**: 100.29.147.161

---

### Flag 13 – Scheduled Re-Execution Persistence

**Objective** <br>
Identify mechanisms that ensure the attacker’s tooling will automatically run again after a reboot or user sign-in.

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

<br>

**Findings**
- User executed command `/Create /SC ONLOGON /` with their support-themed "tool"
- Full command:
   - "schtasks.exe" /Create /SC ONLOGON /TN SupportToolUpdater /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\g4bri3lintern\Downloads\SupportTool.ps1"" /RL LIMITED /F
     
**Analysis**
- Scheduled task ensures `SupportToolUpdater.ps1` runs on user logon

** Flag Answer (Task Name)**: SupportToolUpdater

---

### Flag 14 – Autorun Fallback Persistence

**Objective** <br>
Identify lightweight persistence mechanisms created under the user context, specifically autorun entries in the registry or startup directory.

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

<br>

**Findings**
- The query returned no results, as noted in the scenario instructions
- Answer was given as RemoteAssistUpdater

**Analysis**
- Fallback autorun entry increases persistence resilience
- Appears redundant along with the previously created scheduled task, but using both increases flexibility and ensures execution even if one mechanism fails

**Flag Answer (Registry Value Name)**: RemoteAssistUpdater

---

### Flag 15 – Planted Narrative / Cover Artifact

**Objective** <br>
Identify any artifacts deliberately created to justify, disguise, or mislead investigators regarding the nature of the suspicious activity. 

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

<br>

**Findings**
- User created a shortcut file named `SupportChat_log.lnk`

**Analysis**
- A user-facing file mimicking a helpdesk chat to justify suspicious activity
- File was manually opened via `Explorer.exe`
- File naming convention implies a support troubleshooting log
- File size increased slightly after modification to mimic the addition of routine notes or updates

**Flag Answer (Artifact File Name)**: SupportChat_log.lnk

---

## Recommended Response Actions

### 1. Host Containment & Credential Safeguards
- Isolate the affected host `gab-intern-vm` from the network.
- Rotate credentials for the intern account and any accounts active on the host.
- Review lateral movement attempts across nearby systems.

### 2. Artifact & Process Review
- Retrieve and analyze the following artifacts:
  - `supporttool.ps1`
  - `ReconArtifacts.zip`
  - `SupportChat_log.lnk`
  - Any remaining persistence artifacts (`Scheduled Tasks`, `Run` keys)

- Confirm whether the ZIP contains sensitive data or staged reconnaissance output.

### 3. Persistence Cleanup
- Remove the scheduled task **SupportToolUpdater**.
- Remove registry autorun value **RemoteAssistUpdater**.
- Verify there are no additional hidden persistence mechanisms.

### 4. Network & Egress Monitoring
- Review outbound connections around:
  - `www.msftconnecttest.com`
  - `httpbin.org` (100.29.147.161)

- Validate whether similar egress tests have been performed on other hosts.

### 5. Enterprise-wide Threat Hunt
Perform broader detections across the environment for:
- Execution of PowerShell with `-ExecutionPolicy Bypass`
- Use of `qwinsta`, `tasklist /v`, `whoami /groups` outside admin timelines
- Creation of ZIP files in `C:\Users\Public\`
- Scheduled task creation from user context
- Autorun registry entries created by non-admin users

### 6. Policy & Control Adjustments
- Restrict execution from user Downloads directories.
- Enforce PowerShell Constrained Language Mode for non-admin accounts.
- Implement stricter egress controls and external destination allowlisting.
- Enable tamper protection and script block logging.

### 7. User Education & Process Review
- Train users to escalate suspicious “IT support” interactions.
- Review access policies for interns and low‑privilege users.

### 8. Post-Incident Summary
- Document the root cause: user-context script execution masked as IT support.
- Identify opportunities to improve detection coverage (PowerShell logs, task creation auditing).
- Apply lessons learned into future SOC playbooks.

---

## MITRE ATT&CK Mapings

### Initial Access & Execution
- **T1059.001 – Command and Scripting Interpreter: PowerShell**  
  Execution of `supporttool.ps1` with `-ExecutionPolicy Bypass`.
- **T1059 – Command and Scripting Interpreter**  
  Repeated execution of commands (`qwinsta`, `tasklist`, `whoami`, etc.).

### Defense Evasion
- **T1562 – Impair Defenses**  
  Creation of `DefenderTamperArtifact.lnk`, suggesting intent to mimic tampering or assess defensive posture.
- **T1218 – Signed Binary Proxy Execution**  
  Using `schtasks.exe`, `wmic`, and `cmd.exe` to execute or launch tasks.

### Discovery (Reconnaissance)
- **T1082 – System Information Discovery**  
  Querying host info (`tasklist`, `cmd`, runtime enumeration).
- **T1033 – Account Discovery**  
  `whoami /groups`, privilege review.
- **T1087 – Account Discovery**  
  Session/user enumeration via `qwinsta`, `query session`, `quser`.
- **T1016 – System Network Configuration Discovery**  
  Use of `ipconfig`, outbound connectivity tests.
- **T1046 – Network Service Scanning** *(soft alignment)*  
  Testing external reachability via `msftconnecttest.com`.
- **T1083 – File and Directory Discovery**  
  Storage enumeration via `wmic logicaldisk`.
- **T1119 – Automated Collection**  
  Clipboard probing via `Get-Clipboard`.

### Collection & Staging
- **T1074 – Data Staged**  
  Recon artifacts consolidated as `ReconArtifacts.zip` in `C:\Users\Public\`.

### Command and Control / Egress
- **T1041 – Exfiltration Over Command and Control Channel**  
  Outbound HTTPS communication to `httpbin.org`.
- **T1105 – Ingress Tool Transfer / Generic Network Communication**  
  Network testing via PowerShell to external endpoints.

### Persistence
- **T1053.005 – Scheduled Task/Job: Scheduled Task**  
  Creation of `SupportToolUpdater` to execute on logon.
- **T1547.001 – Boot or Logon Autostart Execution: Registry Run Key**  
  Registry persistence via `RemoteAssistUpdater`.

### Defense Evasion / Impacted Analyst Deception
- **T1036 – Masquerading**  
  Support-themed naming (`supporttool.ps1`, `supportchat_log.lnk`).
- **T1204 – User Execution / Social Engineering** *(light alignment)*  
  Placement of misleading “support log” file to disguise activity.

# Conclusion

The activity observed on `gab-intern-vm` was not consistent with IT support but aligned with structured reconnaissance and light persistence staging. Although no confirmed exfiltration occurred, the operator demonstrated intent and capability through system enumeration, privilege checks, outbound connectivity testing, and creation of scheduled and autorun-based persistence mechanisms.

Across all stages, the behavior showed planning, sequencing, and purposeful artifact creation rather than accidental or legitimate support operations. The findings confirm that the host was being probed for future access, not repaired.
