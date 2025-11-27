# Threat Hunting Lab: “IT Support” Recon Simulation
Scenario

A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection. Your mission: reconstruct the timeline, connect the scattered remnants of this “support session,” and decide what was legitimate versus staged.

Suspicious VM: gab-intern-vm

Starting Point

Before diving into flags, hunting started here:

Intel:

Multiple machines were spawning processes from Downloads folders during early October.

Shared file traits: similar executables, naming patterns, keywords (desk, help, support, tool).

Intern-operated machines were affected.

---

Initial KQL Query – Suspicious Files in Downloads:

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
<kbd>
<img width="1600" height="266" alt="image" src="https://github.com/user-attachments/assets/c3f42ce6-c560-4635-9821-02b77b58d4ab" />
</kbd>
   
<kbd>
<img width="1176" height="370" alt="image" src="https://github.com/user-attachments/assets/8a94ba72-f499-4b41-941b-b75f903a23f0" />
</kbd>

---

Flag Walkthrough
### Flag 1 – Initial Execution Detection

Objective: Detect the earliest anomalous execution representing an entry point.

What to Hunt: Atypical scripts or commands outside normal user behavior.

Hint: Downloads; Two.

Answer: -ExecutionPolicy

Query:

```kql
let filelaunch = todatetime('2025-10-09T12:22:27.6514901Z');
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains ".ps1"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName, ProcessCommandLine
| where TimeGenerated between (filelaunch -5m .. filelaunch + 5m)
| order by TimeGenerated desc
```
<kbd>
<img width="1294" height="424" alt="image" src="https://github.com/user-attachments/assets/8993ee49-ee47-435d-b560-89fff8755430" />
</kbd>

Analysis:
-ExecutionPolicy Bypass allows PowerShell to execute scripts without signature enforcement, commonly leveraged in attacks to run malicious .ps1 files.

---

### Flag 2 – Defense Disabling

Objective: Identify simulated or staged security posture changes.

Hint: File was manually accessed.

Answer: DefenderTamperArtifact.lnk

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

Analysis:
The artifact represents intent to indicate defense tampering; actual configuration changes may not have occurred.

---

### Flag 3 – Quick Data Probe

Objective: Spot opportunistic checks for sensitive content.

Hint: Clipboard check.

Answer: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

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

Analysis:
Actors probe clipboards for passwords, tokens, or keys. Extremely short-lived reconnaissance.

---

### Flag 4 – Host Context Recon

Objective: Collect host and user context for planning follow-up actions.

Hint: qw (qwinsta)

Answer (Last Recon Attempt Timestamp): 2025-10-09T12:51:44.3425653Z

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

Analysis:
qwinsta.exe enumerates logged-in users and session info; standard recon technique.

---

### Flag 5 – Storage Surface Mapping

Objective: Detect enumeration of local/network storage.

Hint: Storage assessment.

Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size

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

---

### Flag 6 – Connectivity & Name Resolution Check

Objective: Identify network reachability and DNS queries.

Hint: Session query.

Answer: RuntimeBroker.exe

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

---

### Flag 7 – Interactive Session Discovery

Objective: Detect enumeration of active user sessions.

Answer (Unique ID of Initiating Process): 2533274790397065

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

---

### Flag 8 – Runtime Application Inventory

Answer (Process FileName): tasklist.exe

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

---

### Flag 9 – Privilege Surface Check

Answer (Timestamp of first attempt): 2025-10-09T12:52:14.3135459Z

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

---

### Flag 10 – Proof-of-Access & Egress Validation

Answer (First Outbound Destination): www.msftconnecttest.com

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

---

### Flag 11 – Bundling / Staging Artifacts

Answer (File Path): C:\Users\Public\ReconArtifacts.zip

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

---

### Flag 12 – Outbound Transfer Attempt (Simulated)

Answer (IP of last unusual outbound connection): 100.29.147.161

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

---

### Flag 13 – Scheduled Re-Execution Persistence

Answer (Task Name): SupportToolUpdater

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

---

### Flag 14 – Autorun Fallback Persistence

Answer (Registry Value Name): RemoteAssistUpdater

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

---

### Flag 15 – Planted Narrative / Cover Artifact

Answer (Artifact File Name): SupportChat_log.lnk

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

---

Analysis:
A user-facing file mimicking a helpdesk chat to justify suspicious activity.

Timeline & Analyst Reasoning <br>
Step	Objective	Analyst Note <br>
0 → 1	Initial Execution	SupportTool.ps1 appears in Downloads; executed with bypass flag. <br>
1 → 2	Defense Disabling	Evidence of tamper artifacts; intent observed. <br>
2 → 3	Quick Data Probe	Clipboard checked for sensitive info. <br>
3 → 4	Host Recon	User/session enumeration via qwinsta. <br>
4 → 5	Storage Mapping	Drives enumerated (wmic logicaldisk). <br>
5 → 6	Connectivity Check	Network/DNS verified. <br>
6 → 7	Interactive Session	Active sessions discovered. <br>
7 → 8	Runtime Inventory	tasklist.exe snapshot taken. <br>
8 → 9	Privilege Check	whoami /groups and /priv run. <br>
9 → 10	Proof-of-Access	Files + first outbound test (www.msftconnecttest.com). <br>
10 → 11	Bundling	ReconArtifacts.zip created for exfil. <br>
11 → 12	Outbound Test	HTTPS upload to httpbin.org. <br>
12 → 13	Scheduled Task	SupportToolUpdater ensures re-execution. <br>
13 → 14	Autorun Fallback	RemoteAssistUpdater registry entry. <br>
14 → 15	Narrative	SupportChat_log.lnk as planted justification. <br>

