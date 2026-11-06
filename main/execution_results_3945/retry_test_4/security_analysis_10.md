[IOC] SourceImage = "wiseman.EXE" | Source: filename 'wiseman.EXE'  

[BEHAVIOR] SourceImage = * (any non‑UI service or background process) AND TargetImage = "winlogon.exe" AND GrantedAccess contains PROCESS_VM_READ OR PROCESS_VM_WRITE OR PROCESS_CREATE_PROCESS | Source: T1056.001  

[BEHAVIOR] SourceImage = * (any non‑UI service or background process) AND TargetImage = "osk.exe" AND GrantedAccess contains PROCESS_VM_READ OR PROCESS_VM_WRITE OR PROCESS_CREATE_PROCESS | Source: T1056.001  

[BEHAVIOR] SourceImage = * (any process) AND TargetImage = "lsass.exe" AND GrantedAccess contains PROCESS_VM_READ OR PROCESS_QUERY_INFORMATION | Source: T1134  

[DERIVED] SourceImage = * (any process that appears after a network‑based exploit) AND TargetImage = "lsass.exe" AND GrantedAccess = 0x1FFFFF (full‑access) | Source: CVE-2023-27350  

**Omitted IOC explanation**: The indicator “wininet.dll” is a DLL name, not an executable that can appear as SourceImage or TargetImage in Sysmon Event ID 10 (process‑access). Consequently, it cannot be directly monitored with this event type, so it is excluded from the recommendations.