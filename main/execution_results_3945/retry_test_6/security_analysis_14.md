[IOC] EventType: RenameKey, Image: wiseman.exe, TargetObject: *, NewName: * | Source: IOC filename (wiseman.EXE)  
[DERIVED] EventType: RenameKey, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\*, NewName: * | Source: T1543.003 (Windows Service)  
[DERIVED] EventType: RenameKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run*, NewName: * | Source: T1547.001 (Registry Run Keys / Startup Folder)  
[DERIVED] EventType: RenameKey, Image: *, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run*, NewName: * | Source: T1547.001 (Registry Run Keys / Startup Folder)

**Why other items were not included**

- **T1056.001 (Keylogging)** – The technique focuses on capturing keystrokes via API hooks, drivers, or hardware buffers. It does not involve renaming registry keys or values, which is the only activity EventID 14 can record. Hence no relevant recommendation.

- **T1082 (System Information Discovery)** – This technique gathers OS and hardware data through commands or API calls. It does not modify or rename registry entries, so EventID 14 provides no observable data for this pattern.

- **T1012 (Query Registry)** – Querying the registry reads data; it does not perform rename operations. EventID 14 captures only rename events, so this technique yields no actionable monitoring requirement.

- **wininet.dll (IoC filename)** – The indicator is a DLL name, not a process that could appear in the “Image” field of a Sysmon rename event. Since EventID 14 logs the process image performing the rename, monitoring the DLL directly is not feasible.

- **CVE‑2023‑27350** – The vulnerability is an authentication bypass in PaperCut NG that allows arbitrary code execution as SYSTEM. The description does not mention any registry rename activity; therefore EventID 14 cannot be leveraged to detect exploitation of this CVE.