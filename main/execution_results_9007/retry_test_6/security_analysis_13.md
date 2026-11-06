[BEHAVIOR] EventType: SetValue, Image: services.exe|sc.exe|net.exe|psexec.exe, TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*\Start, Details: DWORD value indicating service start type (e.g., 0=Boot, 2=Auto, 3=Manual, 4=Disabled) | Source: T1569.002  

[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode, Details: DWORD value (0 = disabled, 1 = enabled) | Source: T1112  

[BEHAVIOR] EventType: SetValue, Image: *, TargetObject: HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR, Details: DWORD value (0 = System Restore enabled, 1 = disabled) | Source: T1490  

[DERIVED] EventType: SetValue, Image: *, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA, Details: DWORD value (0 = UAC disabled, 1 = UAC enabled) | Source: T1219