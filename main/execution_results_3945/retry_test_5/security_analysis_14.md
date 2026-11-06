[BEHAVIOR] EventType=RenameKey, Image=reg.exe, TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run, NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey, Image=reg.exe, TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce, NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey, Image=powershell.exe, TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run, NewName=* | Source: T1547.001  
[BEHAVIOR] EventType=RenameKey, Image=sc.exe, TargetObject=HKLM\SYSTEM\CurrentControlSet\Services\*, NewName=* | Source: T1543.003  
[BEHAVIOR] EventType=RenameKey, Image=reg.exe, TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run, NewName=* | Source: T1112  
[IOC] EventType=RenameKey, Image=wiseman.EXE, TargetObject=*, NewName=* | Source: IOC filename wiseman.EXE  
[IOC] EventType=RenameKey, Image=wininet.dll, TargetObject=*, NewName=* | Source: IOC filename wininet.dll  

**Omitted context explanations**  
- **T1056.001 (Keylogging)** – The technique focuses on capturing keystrokes and does not involve registry key or value rename operations; therefore it cannot be observed with Sysmon EventID 14.  
- **T1082 (System Information Discovery)** – This technique gathers OS and hardware details and does not perform registry renames, so it is outside the scope of EventID 14.  
- **CVE‑2023‑27350 (PaperCut NG)** – The vulnerability description mentions authentication bypass and arbitrary code execution but provides no indication of registry rename activity; thus it cannot be directly monitored via EventID 14.