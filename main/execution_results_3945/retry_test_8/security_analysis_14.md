[IOC] EventType: RenameKey, Image: wiseman.exe, TargetObject: *, NewName: * | Source: IOC filename wiseman.EXE  
[IOC] EventType: RenameKey, Image: wininet.dll, TargetObject: *, NewName: * | Source: IOC filename wininet.dll  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run*, NewName: * | Source: T1547.001  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce*, NewName: * | Source: T1547.001  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices*, NewName: * | Source: T1112  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\*, NewName: * | Source: T1112  

**Explanation of omitted items**  
- **T1056.001 (Keylogging)** – This technique focuses on capturing keystrokes, not on modifying or renaming registry keys, so Sysmon EventID 14 (registry rename) does not capture relevant activity.  
- **T1543.003 (Windows Service creation/modification)** – While service creation/modification often writes new registry values, the technique does not normally involve renaming existing keys or values, therefore no rename‑specific monitoring can be derived.  
- **T1082 (System Information Discovery)** – This technique is limited to querying system information and does not manipulate the registry, so rename events are not applicable.  
- **T1012 (Query Registry)** – Querying the registry reads data; it does not perform rename operations, thus EventID 14 is not useful for detecting this behavior.  
- **CVE‑2023‑27350** – The vulnerability description references an “improper access control” in the SetupCompleted class but does not specify any registry key rename activity. Consequently, there is no direct evidence to justify a rename‑specific monitor for this CVE.