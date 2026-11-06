[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\* NewName: * | Source: T1569.002 – Service Execution (rename of service registry keys to hide or modify malicious services)  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\* NewName: * | Source: T1112 – Modify Registry (persistence via Run keys)  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\* NewName: * | Source: T1112 – Modify Registry (persistence via RunOnce keys)  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\* NewName: * | Source: T1490 – Inhibit System Recovery (tampering with backup‑restore configuration keys)  
[IOC] EventType: RenameKey Image: *\h3odp7l2u.exe TargetObject: * NewName: * | Source: IOC filename h3odp7l2u.exe  
[IOC] EventType: RenameKey Image: *\hi9lezv.exe TargetObject: * NewName: * | Source: IOC filename hi9lezv.exe  
[IOC] EventType: RenameKey Image: *\072wiof7.exe TargetObject: * NewName: * | Source: IOC filename 072wiof7.exe  
[IOC] EventType: RenameKey Image: *\k0d649u.exe TargetObject: * NewName: * | Source: IOC filename k0d649u.exe  
[IOC] EventType: RenameKey Image: *\inc.exe TargetObject: * NewName: * | Source: IOC filename inc.exe  

**Explanation of omitted items**  
The remaining IOC filenames (e.g., x86_64-unknown-linux-esxi.elf, 2026‑03‑08_ec37…_glassworm, win.bin, etc.) are either non‑Windows executables, Linux binaries, or generic payload names with no documented capability to perform Registry operations; therefore they cannot generate Sysmon EventID 14 events on Windows and are excluded.  

The CVE entries (CVE‑2023‑3519, CVE‑2023‑48788, CVE‑2024‑57727, CVE‑2025‑5777) describe remote code execution, SQL injection, path‑traversal, and memory‑overread vulnerabilities that do not explicitly involve Registry key renaming, so they are not represented in the recommendations.  

The attack pattern T1219 (Remote Access Tools) is retained only insofar as it can lead to the behaviors covered by the BEHAVIOR rules above (e.g., remote tools modifying service or Run keys); no additional rename‑specific indicator is directly stated, so no separate recommendation is added.