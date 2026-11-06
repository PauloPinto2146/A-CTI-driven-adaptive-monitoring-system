[IOC] EventType: RenameKey Image: any executable from the IOC filename list (e.g., h3odp7l2u.exe, hi9lezv.exe, 072wiof7.exe, …) TargetObject: * TargetObject: * NewName: * | Source: IOC filenames  

[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\* NewName: * | Source: T1569.002  

[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run* NewName: * | Source: T1112  

[DERIVED] EventType: RenameKey Image: * TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon* NewName: * | Source: T1219  

[DERIVED] EventType: RenameKey Image: * TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Recovery* NewName: * | Source: T1490