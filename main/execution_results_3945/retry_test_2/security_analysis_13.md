[IOC] EventType: SetValue, Image: *\wiseman.EXE, TargetObject: any registry key, Details: DWORD/QWORD value written | Source: filename wiseman.EXE  
[IOC] EventType: SetValue, Image: *\wininet.dll, TargetObject: any registry key, Details: DWORD/QWORD value written | Source: filename wininet.dll  
[BEHAVIOR] EventType: SetValue, Image: sc.exe | powershell.exe | any service‑creation/modification process, TargetObject: HKLM\System\CurrentControlSet\Services\*\Start, Details: DWORD startup type changed (e.g., 0x2, 0x3) | Source: T1543.003  
[BEHAVIOR] EventType: SetValue, Image: sc.exe | powershell.exe | any service‑creation/modification process, TargetObject: HKLM\System\CurrentControlSet\Services\*\Type, Details: DWORD service type value modified | Source: T1543.003  
[BEHAVIOR] EventType: SetValue, Image: any process, TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode, Details: DWORD value set to 0 or 1 (disable/enable) | Source: T1112  

**Omitted items and rationale**  
- **T1056.001 (Keylogging)** – The technique’s registry‑based implementations involve value types such as REG_SZ/REG_BINARY for hook configuration, not DWORD/QWORD, so EventID 13 would not capture relevant activity.  
- **T1082 (System Information Discovery)** – This technique uses registry *queries* (read‑only) to gather OS details; EventID 13 only logs modifications, therefore it cannot observe this behavior.  
- **T1012 (Query Registry)** – Likewise, this technique is purely read‑only; no SetValue events are generated.  
- **T1547.001 (Registry Run Keys / Startup Folder)** – Persistence via Run/RunOnce keys stores the executable path as REG_SZ (or REG_EXPAND_SZ), not as DWORD/QWORD, which EventID 13 does not record.  
- **CVE‑2023‑27350 (PaperCut NG authentication bypass)** – The disclosed vulnerability is a remote code execution flaw that does not involve Windows Registry modifications of DWORD/QWORD type, so it cannot be monitored with EventID 13.  