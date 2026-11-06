[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*, Details: * | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\*, Details: * | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\*\ImagePath, Details: * | Source: T1569.002  
[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\*\Description, Details: * | Source: T1569.002  
[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit, Details: * | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, Details: * | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode, Details: * | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\*\Start, Details: * | Source: T1490  

**Explanation of omitted IOCs:**  
The provided list of malicious filenames (e.g., h3odp7l2u.exe, inc.exe) are indicators of file‑based execution. Sysmon Event ID 13 records only Registry value writes and does not capture process creation, file writes, or executable launches. Consequently, no filename‑based IOC can be monitored using this event type, so they were omitted from the recommendations. Likewise, the CVE entries describe network‑oriented vulnerabilities (remote code execution, path traversal, memory over‑read) that do not manifest as specific Registry value modifications, and therefore they do not yield observable SetValue events.