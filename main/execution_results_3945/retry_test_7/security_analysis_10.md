[BEHAVIOR] SourceImage: * , TargetImage: C:\Windows\System32\lsass.exe , GrantedAccess: PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION , CallTrace: kernel32.dll!OpenProcess → (any caller) | Source: T1134  

[BEHAVIOR] SourceImage: * , TargetImage: C:\Windows\System32\winlogon.exe , GrantedAccess: PROCESS_ALL_ACCESS , CallTrace: user32.dll!SetWindowsHookEx → (any caller) | Source: T1056.001  

[BEHAVIOR] SourceImage: * , TargetImage: C:\Windows\System32\osk.exe , GrantedAccess: PROCESS_ALL_ACCESS , CallTrace: user32.dll!SetWindowsHookEx → (any caller) | Source: T1056.001  

[BEHAVIOR] SourceImage: * , TargetImage: * , GrantedAccess: TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | PROCESS_CREATE_PROCESS , CallTrace: advapi32.dll!DuplicateTokenEx → (any caller) | Source: T1134  

[IOC] SourceImage: *\wiseman.EXE , TargetImage: * , GrantedAccess: PROCESS_ALL_ACCESS , CallTrace: * (any) | Source: IOC filename wiseman.EXE  

*Why wininet.dll is omitted*: Sysmon Event ID 10 only records when a **process** opens another **process**. The indicator “wininet.dll” is a DLL, not an executable process, and therefore cannot be observed via a Process Access event. Consequently it is not applicable to this monitoring scope.  

*Why T1140 (Deobfuscate/Decode) is omitted*: The techniques described for T1140 involve using tools such as certutil.exe, PowerShell, or copy.exe to decode files. These actions are captured by process creation (Event 1) or command‑line monitoring, not by Process Access (Event 10). Hence no relevant Process Access observation can be derived from the deobfuscation pattern.  