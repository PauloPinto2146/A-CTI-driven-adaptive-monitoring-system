[IOC] EventType: RenameKey, Image: x86_64-unknown-linux-esxi.elf, TargetObject: *, NewName: * | Source: filename x86_64-unknown-linux-esxi.elf  
[IOC] EventType: RenameKey, Image: h3odp7l2u.exe, TargetObject: *, NewName: * | Source: filename h3odp7l2u.exe  
[IOC] EventType: RenameKey, Image: hi9lezv.exe, TargetObject: *, NewName: * | Source: filename hi9lezv.exe  
[IOC] EventType: RenameKey, Image: 072wiof7.exe, TargetObject: *, NewName: * | Source: filename 072wiof7.exe  
[IOC] EventType: RenameKey, Image: k0d649u.exe, TargetObject: *, NewName: * | Source: filename k0d649u.exe  
[IOC] EventType: RenameKey, Image: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, TargetObject: *, NewName: * | Source: filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType: RenameKey, Image: 2qfguc.exe, TargetObject: *, NewName: * | Source: filename 2qfguc.exe  
[IOC] EventType: RenameKey, Image: 7hhel.exe, TargetObject: *, NewName: * | Source: filename 7hhel.exe  
[IOC] EventType: RenameKey, Image: 3ctjhm3.exe, TargetObject: *, NewName: * | Source: filename 3ctjhm3.exe  
[IOC] EventType: RenameKey, Image: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, TargetObject: *, NewName: * | Source: filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType: RenameKey, Image: bjiw49.exe, TargetObject: *, NewName: * | Source: filename bjiw49.exe  
[IOC] EventType: RenameKey, Image: 7l73h.exe, TargetObject: *, NewName: * | Source: filename 7l73h.exe  
[IOC] EventType: RenameKey, Image: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, TargetObject: *, NewName: * | Source: filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType: RenameKey, Image: 0m6m882x2.exe, TargetObject: *, NewName: * | Source: filename 0m6m882x2.exe  
[IOC] EventType: RenameKey, Image: inc.exe, TargetObject: *, NewName: * | Source: filename inc.exe  
[IOC] EventType: RenameKey, Image: 61pd6n3t.exe, TargetObject: *, NewName: * | Source: filename 61pd6n3t.exe  
[IOC] EventType: RenameKey, Image: mk1yd.exe, TargetObject: *, NewName: * | Source: filename mk1yd.exe  
[IOC] EventType: RenameKey, Image: a3mnw9.exe, TargetObject: *, NewName: * | Source: filename a3mnw9.exe  
[IOC] EventType: RenameKey, Image: win.bin, TargetObject: *, NewName: * | Source: filename win.bin  
[IOC] EventType: RenameKey, Image: vw06lg0y.exe, TargetObject: *, NewName: * | Source: filename vw06lg0y.exe  
[IOC] EventType: RenameKey, Image: qgp2s6z.exe, TargetObject: *, NewName: * | Source: filename qgp2s6z.exe  
[IOC] EventType: RenameKey, Image: tt24n8xsl.exe, TargetObject: *, NewName: * | Source: filename tt24n8xsl.exe  

[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\*, NewName: * | Source: T1112  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\*, NewName: * | Source: T1112  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*, NewName: * | Source: T1569.002  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, NewName: * | Source: T1112  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit, NewName: * | Source: T1112  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: *SafeDllSearchMode*, NewName: * | Source: T1112  

[DERIVED] EventType: RenameKey, Image: *, TargetObject: *\0*, NewName: * | Source: T1112 (pseudo‑hidden registry keys)