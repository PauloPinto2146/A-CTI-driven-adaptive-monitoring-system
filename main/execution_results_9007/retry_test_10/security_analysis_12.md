[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  

[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce | Source: T1219  

[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  

[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce | Source: T1219  

[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\System\CurrentControlSet\Services\* | Source: T1219  

**Explanation for omitted IoCs and attack patterns**  
The provided list of file‑based indicators of compromise (e.g., “h3odp7l2u.exe”, “inc.exe”, etc.) cannot be captured by Sysmon Event ID 12 because this event type only records registry key creation and deletion, not file creation, execution, or hash information. Likewise, the ATT&CK technique identifier T1219 describes remote access tool usage; while its behavioral description mentions persistence via services and autostart registry locations (which we monitor), the technique itself does not specify concrete registry keys or values to watch. Therefore, no direct IoC‑specific recommendations are possible for this event type, and the analysis focuses solely on the relevant registry‑based persistence behaviors derived from T1219.