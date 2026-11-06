[BEHAVIOR] EventType: SetValue, Image: *\sc.exe*, TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*, Details: ServiceImagePath (DWORD/QWORD) persistence or execution | Source: T1569.002  
[BEHAVIOR] EventType: SetValue, Image: *\bcdedit.exe*, TargetObject: HKLM\BCD00000000\Elements\*, Details: bootstatuspolicy / recoveryenabled flags (DWORD) disabling recovery | Source: T1490  
[BEHAVIOR] EventType: SetValue, Image: *\REAgentC.exe*, TargetObject: HKLM\SOFTWARE\Microsoft\Recovery\*, Details: WinRE disabled flag (DWORD) | Source: T1490  
[BEHAVIOR] EventType: SetValue, Image: *\reg.exe*, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run*, Details: Persistence entry (DWORD/QWORD) for auto‑run binaries | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *\reg.exe*, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Winlogon\Userinit, Details: Modified Userinit path (DWORD/QWORD) | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *\reg.exe*, TargetObject: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, Details: Modified Shell value (DWORD/QWORD) | Source: T1112  
[BEHAVIOR] EventType: SetValue, Image: *\reg.exe*, TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode, Details: Disabled SafeDllSearchMode (DWORD) | Source: T1112  
[IOC] EventType: SetValue, Image: *\h3odp7l2u.exe*, TargetObject: *, Details: * | Source: h3odp7l2u.exe  
[IOC] EventType: SetValue, Image: *\inc.exe*, TargetObject: *, Details: * | Source: inc.exe  
[IOC] EventType: SetValue, Image: *\win.bin*, TargetObject: *, Details: * | Source: win.bin  
[IOC] EventType: SetValue, Image: *\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat*, TargetObject: *, Details: * | Source: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat  