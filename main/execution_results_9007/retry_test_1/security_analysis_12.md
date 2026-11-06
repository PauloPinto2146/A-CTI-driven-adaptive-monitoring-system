[BEHAVIOR] EventType: CreateKey, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *, TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey, Image: *, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey, Image: *, TargetObject: HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *, TargetObject: HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  

**Explanation:** The provided indicators of compromise consist solely of executable filenames (e.g., `h3odp7l2u.exe`, `win.bin`). Sysmon Event ID 12 records only registry key creation and deletion events; it does not capture file creation, modification, or execution. Consequently, none of the listed filenames can be directly monitored via this event type, and they are omitted from the recommendations. Similarly, the CVE descriptions do not mention registry modifications, so no registry‑specific alerts can be derived from those vulnerabilities. The recommendations focus exclusively on registry persistence mechanisms described in ATT&CK technique T1219, which are observable with Event ID 12.