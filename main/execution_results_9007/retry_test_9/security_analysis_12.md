[BEHAVIOR] EventType: CreateKey, Image: C:\Windows\System32\sc.exe, TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: C:\Windows\System32\sc.exe, TargetObject: HKLM\System\CurrentControlSet\Services\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey, Image: *\rundll32.exe, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *\rundll32.exe, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: CreateKey, Image: *\reg.exe, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[BEHAVIOR] EventType: DeleteKey, Image: *\reg.exe, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\* | Source: T1219  
[DERIVED] EventType: CreateKey, Image: C:\Program Files\SimpleHelp\SimpleHelp.exe, TargetObject: HKLM\Software\SimpleHelp\* | Source: CVE-2024-57727  
[DERIVED] EventType: DeleteKey, Image: C:\Program Files\SimpleHelp\SimpleHelp.exe, TargetObject: HKLM\Software\SimpleHelp\* | Source: CVE-2024-57727  