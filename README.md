# Threat-Hunt

Threat Hunting Lab: “IT Support” Recon Simulation
Scenario

A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection. Your mission: reconstruct the timeline, connect the scattered remnants of this “support session,” and decide what was legitimate versus staged.

SUS VM: gab-intern-vm

Starting Point

Before diving into flags, hunting started here:

Intel:

Multiple machines were spawning processes from Downloads folders during early October.

Shared file traits: similar executables, naming patterns, keywords (desk, help, support, tool).

Intern-operated machines were affected.

Initial KQL Query – Suspicious Files in Downloads:

DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01)..datetime(2025-10-15))
| where FolderPath contains "download"
| where FileName contains "support"
   or FileName contains "tool"
   or FileName matches regex "desk(!top)"
   or FileName contains "help"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by TimeGenerated desc

Flag Walkthrough
Flag 1 – Initial Execution Detection

Objective: Detect the earliest anomalous execution representing an entry point.

What to Hunt: Atypical scripts or commands outside normal user behavior.

Hint: Downloads; Two.

Answer: -ExecutionPolicy

Query:

let filelaunch = todatetime('2025-10-09T12:22:27.6514901Z');
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains ".ps1"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName, ProcessCommandLine
| where TimeGenerated between (filelaunch -5m .. filelaunch + 5m)
| order by TimeGenerated desc


Analysis:
-ExecutionPolicy Bypass allows PowerShell to execute scripts without signature enforcement, commonly leveraged in attacks to run malicious .ps1 files.

Flag 2 – Defense Disabling

Objective: Identify simulated or staged security posture changes.

Hint: File was manually accessed.

Answer: DefenderTamperArtifact.lnk

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where TimeGenerated between (T1..T2)
| where DeviceName == "gab-intern-vm"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by TimeGenerated desc


Analysis:
The artifact represents intent to indicate defense tampering; actual configuration changes may not have occurred.

Flag 3 – Quick Data Probe

Objective: Spot opportunistic checks for sensitive content.

Hint: Clipboard check.

Answer: "powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where TimeGenerated between (T1 .. T2)
| where DeviceName == "gab-intern-vm"
| where FileName contains "clip"
   or InitiatingProcessCommandLine contains "clip" 
| order by TimeGenerated desc


Analysis:
Actors probe clipboards for passwords, tokens, or keys. Extremely short-lived reconnaissance.

Flag 4 – Host Context Recon

Objective: Collect host and user context for planning follow-up actions.

Hint: qw (qwinsta)

Answer (Last Recon Attempt Timestamp): 2025-10-09T12:51:44.3425653Z

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T2)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "qwi"
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
| order by TimeGenerated desc


Analysis:
qwinsta.exe enumerates logged-in users and session info; standard recon technique.

Flag 5 – Storage Surface Mapping

Objective: Detect enumeration of local/network storage.

Hint: Storage assessment.

Answer: "cmd.exe" /c wmic logicaldisk get name,freespace,size

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T2)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "wmic"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine, ProcessCommandLine
| order by TimeGenerated desc


Analysis:
Enumeration identifies data locations for later collection.

Flag 6 – Connectivity & Name Resolution Check

Objective: Identify network reachability and DNS queries.

Hint: Session query.

Answer: RuntimeBroker.exe

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where ProcessCommandLine contains "Session"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc


Analysis:
RuntimeBroker initiated cmd.exe /c query session to check interactive sessions — reconnaissance.

Flag 7 – Interactive Session Discovery

Objective: Detect enumeration of active user sessions.

Answer (Unique ID of Initiating Process): 2533274790397065

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where ProcessCommandLine contains "/c"
| project TimeGenerated, InitiatingProcessUniqueId, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName
| order by TimeGenerated asc


Analysis:
Child processes share the same MDE UniqueId, allowing correlation even with different PIDs.

Flag 8 – Runtime Application Inventory

Answer (Process FileName): tasklist.exe

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "list" 
   or InitiatingProcessCommandLine contains "list"
| where TimeGenerated between (T1 .. T2)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc


Analysis:
tasklist.exe enumerates all running processes — standard recon.

Flag 9 – Privilege Surface Check

Answer (Timestamp of first attempt): 2025-10-09T12:52:14.3135459Z

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "who" 
   or InitiatingProcessCommandLine contains "who"
| where TimeGenerated between (T1 .. T2)
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated desc


Analysis:
Privilege and group membership enumeration guides attack strategy.

Flag 10 – Proof-of-Access & Egress Validation

Answer (First Outbound Destination): www.msftconnecttest.com

Queries:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where FileName contains "support" 
| order by TimeGenerated asc
| project TimeGenerated, ActionType, DeviceName, FileName

let T1 = datetime(2025-10-09T12:58:00);
DeviceNetworkEvents
| where TimeGenerated between (T1 - 5m .. T1 + 5m)
| where DeviceName == "gab-intern-vm"
| where ActionType contains "success"
| where RemoteUrl != ""
| order by TimeGenerated asc
| project TimeGenerated, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine


Analysis:
The first contact with an external URL validates outbound connectivity; the files created afterward served as proof-of-access.

Flag 11 – Bundling / Staging Artifacts

Answer (File Path): C:\Users\Public\ReconArtifacts.zip

Query:

let T1 = datetime(2025-10-09);
let T2 = datetime(2025-10-10);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where FileName contains ".zip" 
| order by TimeGenerated asc
| project TimeGenerated, DeviceName, FileName, FolderPath, ActionType


Analysis:
Artifacts consolidated into a ZIP for potential exfiltration.

Flag 12 – Outbound Transfer Attempt (Simulated)

Answer (IP of last unusual outbound connection): 100.29.147.161

Queries:

let T1 = datetime(2025-10-09T12:30:00);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T1 + 2h)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine contains "chat" or InitiatingProcessCommandLine contains "chat"
| order by TimeGenerated desc
| project TimeGenerated, ActionType, FileName, FolderPath, ProcessCommandLine

let T1 = datetime(2025-10-09T13:00:00);
DeviceNetworkEvents
| where TimeGenerated between (T1 .. T1 + 10m)
| where DeviceName == "gab-intern-vm"
| where RemoteIP != ""
| order by TimeGenerated asc
| project TimeGenerated, ActionType, InitiatingProcessCommandLine, InitiatingProcessIntegrityLevel, LocalIP, LocalPort, Protocol, RemoteIP, RemoteIPType, RemotePort, RemoteUrl, ReportId


Analysis:
Outbound HTTPS to httpbin.org via PowerShell demonstrates simulated exfiltration attempt.

Flag 13 – Scheduled Re-Execution Persistence

Answer (Task Name): SupportToolUpdater

Query:

let T1 = datetime(2025-10-09);
DeviceProcessEvents
| where TimeGenerated between (T1 .. T1 + 1d)
| where ProcessCommandLine contains "supporttool"


Analysis:
Scheduled task ensures tooling runs on user logon.

Flag 14 – Autorun Fallback Persistence

Answer (Registry Value Name): RemoteAssistUpdater

Query:

let T1 = datetime(2025-10-09);
DeviceRegistryEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T1 + 1d)
| where ActionType contains "RegistryValueSet" or ActionType contains "RegistryValueModified"


Analysis:
Fallback autorun entry increases persistence resilience.

Flag 15 – Planted Narrative / Cover Artifact

Answer (Artifact File Name): SupportChat_log.lnk

Query:

let T1 = datetime(2025-10-09T12:00:00);
let T2 = datetime(2025-10-09T14:00:00);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (T1 .. T2)
| where FileName contains "support"
| order by TimeGenerated desc


Analysis:
A user-facing file mimicking a helpdesk chat to justify suspicious activity.

Timeline & Analyst Reasoning
Step	Objective	Analyst Note
0 → 1	Initial Execution	SupportTool.ps1 appears in Downloads; executed with bypass flag.
1 → 2	Defense Disabling	Evidence of tamper artifacts; intent observed.
2 → 3	Quick Data Probe	Clipboard checked for sensitive info.
3 → 4	Host Recon	User/session enumeration via qwinsta.
4 → 5	Storage Mapping	Drives enumerated (wmic logicaldisk).
5 → 6	Connectivity Check	Network/DNS verified.
6 → 7	Interactive Session	Active sessions discovered.
7 → 8	Runtime Inventory	tasklist.exe snapshot taken.
8 → 9	Privilege Check	whoami /groups and /priv run.
9 → 10	Proof-of-Access	Files + first outbound test (www.msftconnecttest.com).
10 → 11	Bundling	ReconArtifacts.zip created for exfil.
11 → 12	Outbound Test	HTTPS upload to httpbin.org.
12 → 13	Scheduled Task	SupportToolUpdater ensures re-execution.
13 → 14	Autorun Fallback	RemoteAssistUpdater registry entry.
14 → 15	Narrative	SupportChat_log.lnk as planted justification.

