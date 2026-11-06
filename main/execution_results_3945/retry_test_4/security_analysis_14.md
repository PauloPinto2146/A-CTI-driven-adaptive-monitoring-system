[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\System\CurrentControlSet\Services\* NewName: * | Source: T1543.003  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* NewName: * | Source: T1547.001  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\* NewName: * | Source: T1547.001  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* NewName: * | Source: T1547.001  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices\* NewName: * | Source: T1543.003  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce\* NewName: * | Source: T1543.003  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute NewName: * | Source: T1547.001  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\* NewName: * | Source: T1547.001  
[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* (value rename) NewName: * | Source: T1547.001  

**Explanation of omitted items**

- **IOC filenames “wiseman.EXE” and “wininet.dll”** – Sysmon EventID 14 records only registry‑key or value rename operations. The presence of a particular executable or DLL is not captured by this event type, so these IOCs cannot be monitored with RenameKey events.

- **CVE‑2023‑27350** – The described PaperCut NG vulnerability is an authentication bypass that results in arbitrary code execution as SYSTEM. The publicly available description does not mention any registry‑rename activity as part of the exploit, therefore no RenameKey‑specific detection can be derived from the CVE.

- **Attack pattern T1056.001 (Keylogging)** – This technique concerns capturing keystrokes; it does not involve renaming registry keys or values, so it is irrelevant to EventID 14.

- **Attack pattern T1082 (System Information Discovery)** – This technique involves gathering OS/hardware details via commands or APIs, not registry rename operations.

- **Attack pattern T1012 (Query Registry)** – Querying registry data does not modify the registry, and therefore does not generate a RenameKey event.

Only the techniques that explicitly manipulate or persist via registry keys/values (T1543.003, T1547.001, and T1112’s broader registry‑modification context) can produce observable RenameKey events, and the recommendations above focus on those relevant persistence locations.