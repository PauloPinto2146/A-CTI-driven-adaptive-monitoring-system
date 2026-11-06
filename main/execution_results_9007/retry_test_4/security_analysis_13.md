[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\reg.exe; TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run; Details: any new DWORD or QWORD value added (persistence) | Source: T1112  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\reg.exe; TargetObject: HKLM\System\CurrentControlSet\Services\*; Details: modifications to service configuration values (e.g., ImagePath, Start) | Source: T1569.002  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\sc.exe; TargetObject: HKLM\System\CurrentControlSet\Services\*; Details: changes to service binary path or startup type | Source: T1569.002  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\powershell.exe; TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify; Details: creation or alteration of subkey/value (persistence/privilege escalation) | Source: T1112  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\powershell.exe; TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit; Details: change of DWORD/QWORD value or string that defines the userinit executable(s) | Source: T1112  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\wmic.exe; TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify; Details: modification of the Notify key via WMI | Source: T1112  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\reg.exe; TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode; Details: change of DWORD value (e.g., from 1 to 0) disabling SafeDllSearchMode | Source: T1112  

[BEHAVIOR] EventType: SetValue; Image: SimpleHelp.exe; TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run; Details: addition of an auto‑start entry by remote‑support software | Source: T1219  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\powershell.exe; TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run; Details: creation of a new DWORD/QWORD value for auto‑run (potential RAT persistence) | Source: T1219  

[BEHAVIOR] EventType: SetValue; Image: C:\Windows\System32\reg.exe; TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA; Details: alteration of the EnableLUA DWORD (UAC bypass) | Source: T1112  