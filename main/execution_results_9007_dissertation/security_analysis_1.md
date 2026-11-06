[IOC] Image equals any of the listed malicious filenames (e.g., h3odp7l2u.exe, hi9lezv.exe, 072wiof7.exe, k0d649u.exe, inc.exe, etc.) | Source: IOC (sha256 + filename list)  
[IOC] Hashes equals any of the provided SHA‑256 values (e.g., 6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141, acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4, …) | Source: IOC (sha256 list)  

[BEHAVIOR] ParentImage is w3wp.exe (IIS worker process) and Image is cmd.exe, powershell.exe, or any non‑standard module load (e.g., msbuild.exe) | Source: T1190  
[BEHAVIOR] CommandLine contains “sc.exe” + “stop”, “delete”, or “config” (service manipulation) | Source: T1489  
[BEHAVIOR] Image equals sc.exe, net.exe, or psexec.exe with arguments that create, modify, or start a service (e.g., “sc create”, “psexec \\target” ) | Source: T1569.002  
[BEHAVIOR] CommandLine contains admin share paths such as “\\C$”, “\\ADMIN$”, or “\\IPC$” (file copy to remote admin share) | Source: T1021.002  
[BEHAVIOR] Image equals reg.exe (or regsvr32.exe) with command‑line arguments that modify registry keys related to persistence or privilege escalation (e.g., Run, Services) | Source: T1112  
[BEHAVIOR] Image equals vssadmin.exe, wbadmin.exe, diskshadow.exe, bcdedit.exe, REAgentC.exe, or wmic.exe with arguments that delete shadow copies, disable recovery, or remove backup catalogs | Source: T1490  
[BEHAVIOR] Image equals cipher.exe, ransomware‑like executables, or any process performing high‑frequency file writes with extensions typical of encrypted payloads (e.g., “.locked”, “.encrypted”) | Source: T1486  
[BEHAVIOR] Image equals ping.exe, tracert.exe, net.exe, or nslookup.exe executed in rapid succession (burst) | Source: T1018  
[BEHAVIOR] Image equals mstsc.exe (Remote Desktop client) or related RDP utilities executed by non‑admin users | Source: T1021.001  
[BEHAVIOR] Image equals FortiClientEMS.exe (or any executable in the FortiClientEMS product) | Source: CVE-2023-48788  
[BEHAVIOR] Image equals SimpleHelp.exe (or related SimpleHelp service executable) | Source: CVE-2024-57727  
[BEHAVIOR] CommandLine contains exploitation patterns targeting known vulnerable services (e.g., “/vulnerable‑endpoint” associated with CVE‑2023‑3519) | Source: CVE-2023-3519  
[DERIVED] ParentImage is a known credential‑dumping tool (e.g., mimikatz.exe, secretsdump.exe) or any process that accesses LSASS (detected by presence of “-accepteula -i” arguments) | Source: T1003  
[DERIVED] Process creation chain where a remote‑access tool (e.g., any process with “-rhost” or “-connect” arguments) installs a service or adds a registry autorun entry, then initiates outbound network connections | Source: T1219  
[DERIVED] Image equals any executable launched from user‑writable or temporary directories (e.g., %TEMP%, %APPDATA%) as indicated by CurrentDirectory path, suggesting potential installation of RAT payloads | Source: T1219  
[DERIVED] CommandLine includes PowerShell commands that download and execute files from external URLs (e.g., “Invoke‑Expression (New‑Object System.Net.WebClient).DownloadString(…)”) | Source: T1190, T1219  
[DERIVED] Image equals any process that runs with High IntegrityLevel and subsequently spawns child processes that perform file encryption or shadow‑copy deletion within a short TimeWindow (≤5 min) | Source: T1486, T1490  