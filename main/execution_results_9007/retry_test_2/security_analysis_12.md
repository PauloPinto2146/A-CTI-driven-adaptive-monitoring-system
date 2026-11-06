[BEHAVIOR] EventType: CreateKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey, Image: *, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  

*Explanation*: The IOC list contains only executable filenames; Sysmon EventID 12 records registry key creation and deletion, not file creation or execution, so those IOC filenames cannot be observed with this event type. The ATT&CK pattern T1219 describes remote‑access tools establishing persistence via autostart registry locations and service registration, which directly maps to the registry‑key monitoring recommendations above. No CVE descriptions reference specific registry modifications, so no additional recommendations are derived from them.