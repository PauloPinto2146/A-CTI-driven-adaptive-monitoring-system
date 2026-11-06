[IOC] EventType: RenameKey, Image: *\reg.exe, powershell.exe, *\cmd.exe, TargetObject: *\Software\Microsoft\Windows\CurrentVersion\Run*, NewName: *wiseman.EXE* | Source: IOC filename wiseman.EXE  
[IOC] EventType: RenameKey, Image: *\reg.exe, powershell.exe, *\cmd.exe, TargetObject: *\Software\Microsoft\Windows\CurrentVersion\Run*, NewName: *wininet.dll* | Source: IOC filename wininet.dll  

[BEHAVIOR] EventType: RenameKey, Image: *\svchost.exe, *\services.exe, TargetObject: HKLM\System\CurrentControlSet\Services\*, NewName: *<any>* | Source: T1543.003 – Windows Service creation/modification (persistence)  

[BEHAVIOR] EventType: RenameKey, Image: *\explorer.exe, *\userinit.exe, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run*, NewName: *<any>* | Source: T1547.001 – Registry Run Keys / Startup Folder persistence  

[DERIVED] EventType: RenameKey, Image: *\services.exe, *\sc.exe, TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute, NewName: *<any>* | Source: Derived from T1547.001 – abuse of BootExecute value for persistence  

---

**Explanation of omitted items**

- **T1056.001 (Keylogging)** – The technique focuses on capturing keystrokes; it does not involve renaming registry keys or values, which is the only activity observable via Sysmon Event ID 14.  

- **T1082 (System Information Discovery)** – This technique gathers OS and hardware details through commands or API calls; it does not perform registry rename operations, so it cannot be detected with Event ID 14.  

- **T1012 (Query Registry)** – Querying registry data reads values but does not modify or rename them; therefore no rename events are generated for this technique.  

- **CVE‑2023‑27350** – The vulnerability allows authentication bypass and arbitrary code execution in the context of SYSTEM for PaperCut NG; the exploit does not specifically manipulate registry keys/values via rename, so it cannot be observed with Event ID 14.  

No other IOC filenames or attack patterns were omitted because they are either directly covered by the recommendations above or are not applicable to rename‑key monitoring.