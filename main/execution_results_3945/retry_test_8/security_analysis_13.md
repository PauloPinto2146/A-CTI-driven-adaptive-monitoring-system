[IOC] SetValue where Image == wiseman.EXE | Source: IOC filename wiseman.EXE  
[IOC] SetValue where Image == wininet.dll | Source: IOC filename wininet.dll  

[BEHAVIOR] SetValue modifications to HKLM\System\CurrentControlSet\Services\<service>\ImagePath (or any value under the service’s key) | Source: T1543.003 – Windows Service  
[BEHAVIOR] SetValue modifications to HKLM\Software\Microsoft\Windows\CurrentVersion\Run* (including Run, RunOnce) | Source: T1547.001 – Registry Run Keys / Startup Folder  
[BEHAVIOR] SetValue modifications to HKCU\Software\Microsoft\Windows\CurrentVersion\Run* (including Run, RunOnce) | Source: T1547.001 – Registry Run Keys / Startup Folder  
[BEHAVIOR] SetValue modifications to HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run | Source: T1547.001 – Registry Run Keys / Startup Folder  
[BEHAVIOR] SetValue modifications to HKLM\System\CurrentControlSet\Control\Session Manager\BootExecute | Source: T1547.001 – Registry Run Keys / Startup Folder  
[BEHAVIOR] SetValue modifications to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit | Source: T1112 – Modify Registry  
[BEHAVIOR] SetValue modifications to HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell | Source: T1112 – Modify Registry  

**Omitted items and rationale**  
- **T1056.001 (Keylogging)** – The technique focuses on capturing keystrokes via API hooking, driver injection, or raw hardware reads. The provided context does not specify any registry keys that are written as part of keylogging, so EventID 13 (SetValue) cannot directly observe this technique.  

- **T1082 (System Information Discovery)** – This technique involves reading system information (e.g., via `systeminfo`), not writing to the registry. Therefore, no SetValue events are associated with this behavior.  

- **T1012 (Query Registry)** – By definition this technique entails reading registry values, not modifying them; EventID 13 only logs value modifications, so it cannot capture this activity.  

- **CVE‑2023‑27350 (PaperCut NG authentication bypass)** – The vulnerability description mentions remote code execution in the context of SYSTEM but does not reference any registry modifications. Consequently, there is no observable SetValue activity directly tied to this CVE.  