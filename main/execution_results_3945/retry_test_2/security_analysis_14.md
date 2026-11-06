[IOC] EventType=RenameKey Image=*wiseman.exe* TargetObject=* NewName=* | Source: IOC filename wiseman.EXE  
[IOC] EventType=RenameKey Image=*wininet.dll* TargetObject=* NewName=* | Source: IOC filename wininet.dll  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKLM\System\CurrentControlSet\Services\* NewName=* | Source: T1543.003  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders\* NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\* NewName=* | Source: T1547.001  

**Explanation of omitted items**  
- **T1056.001 (Keylogging)** – Sysmon EventID 14 records registry rename operations; keylogging does not involve registry renames, so no relevant monitoring can be derived from this event type.  
- **T1082 (System Information Discovery)** – Gathering OS/hardware information is performed via commands or API calls, not through renaming registry keys, thus cannot be observed with EventID 14.  
- **T1012 (Query Registry)** – Querying registry values reads data; it does not modify or rename keys/values, so it is outside the scope of EventID 14.  
- **CVE‑2023‑27350** – The vulnerability description mentions authentication bypass and arbitrary code execution via the *SetupCompleted* class, but provides no indication that it manipulates or renames registry keys. Therefore, no Sysmon RenameKey monitoring can be justified from this CVE.  

Only the techniques that explicitly involve registry key/value renaming (T1112 Modify Registry, T1543.003 Windows Service, T1547.001 Registry Run Keys/Startup Folder) and the provided IOC filenames are included.