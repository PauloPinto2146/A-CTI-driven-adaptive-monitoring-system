[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\* | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\* | Source: T1219  
[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\* | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\* | Source: T1219  

**Explanation:**  
The provided IoCs consist solely of executable filenames (e.g., `h3odp7l2u.exe`, `inc.exe`, etc.). Sysmon Event ID 12 records only Registry key/value creation and deletion; it does not capture file creation, process execution, or network activity. Consequently, these filenames cannot be observed via this event type and were omitted from the recommendations. The analysis therefore focuses exclusively on registry‑based persistence mechanisms described in ATT&CK technique T1219, which are directly observable with Event ID 12.