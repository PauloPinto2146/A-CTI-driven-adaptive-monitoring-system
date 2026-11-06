[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SYSTEM\CurrentControlSet\Services\*, NewName=* | Source: T1569.002  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*, NewName=* | Source: T1112  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\*, NewName=* | Source: T1112  

**Explanation of omitted IoCs**  
The provided indicators of compromise are file names (e.g., `h3odp7l2u.exe`, `win.bin`, etc.). Sysmon Event ID 14 only captures registry key or value rename operations; it does not log file creation, execution, or modification events. Since none of the listed filenames correspond to registry keys or values that could be renamed, they cannot be observed through this event type and are therefore excluded from the monitoring recommendations.