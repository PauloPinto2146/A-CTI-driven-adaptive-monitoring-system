[BEHAVIOR] EventType: RenameKey, Image: *\reg.exe, TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*, NewName: * | Source: T1547.001 (Registry Run Keys / Startup Folder)

[BEHAVIOR] EventType: RenameKey, Image: *\reg.exe, TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\*, NewName: * | Source: T1547.001 (Registry Run Keys / Startup Folder)

[BEHAVIOR] EventType: RenameKey, Image: *\sc.exe, TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*, NewName: * | Source: T1543.003 (Windows Service)

[BEHAVIOR] EventType: RenameKey, Image: *\powershell.exe, TargetObject: HKLM\* or HKCU\*, NewName: * | Source: T1112 (Modify Registry)

[BEHAVIOR] EventType: RenameKey, Image: *\wmic.exe, TargetObject: HKLM\* or HKCU\*, NewName: * | Source: T1112 (Modify Registry)

--- Omitted items explanation ---

- T1056.001 (Keylogging) was omitted because it involves capturing keystrokes and does not perform registry rename operations, which is the only activity that EventID 14 can record.

- T1082 (System Information Discovery) was omitted because it consists of system queries (e.g., systeminfo) and does not modify or rename registry keys/values.

- T1012 (Query Registry) was omitted because it is a read‑only operation; EventID 14 only logs rename (write) actions.

- The IoC filenames “wiseman.EXE” and “wininet.dll” were omitted because the provided context does not indicate that these filenames appear as registry key or value names that are being renamed. Without an explicit claim that the attacker renames a registry entry to these names, they cannot be reliably mapped to a RenameKey event.