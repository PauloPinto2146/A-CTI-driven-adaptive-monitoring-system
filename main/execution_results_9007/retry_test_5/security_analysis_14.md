[BEHAVIOR] EventType: RenameKey, Image: any (e.g., reg.exe, powershell.exe, wmic.exe), TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*, NewName: *(any new name)* | Source: T1112  

[BEHAVIOR] EventType: RenameKey, Image: any (e.g., reg.exe, powershell.exe, wmic.exe), TargetObject: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*, NewName: *(any new name)* | Source: T1112  

[BEHAVIOR] EventType: RenameKey, Image: any (e.g., sc.exe, services.exe, PsExec), TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*, NewName: *(any new name)* | Source: T1569.002  

[DERIVED] EventType: RenameKey, Image: any (e.g., reg.exe, powershell.exe, wmic.exe), TargetObject: any registry key/value, NewName: contains null‑character prefix or other non‑printable/suspicious characters used to hide the key/value | Source: T1112