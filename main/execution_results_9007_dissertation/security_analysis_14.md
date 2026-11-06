[IOC] EventType: RenameKey Image: *\x86_64-unknown-linux-esxi.elf | Source: IOC filename x86_64-unknown-linux-esxi.elf  
[IOC] EventType: RenameKey Image: *\h3odp7l2u.exe | Source: IOC filename h3odp7l2u.exe  
[IOC] EventType: RenameKey Image: *\hi9lezv.exe | Source: IOC filename hi9lezv.exe  
[IOC] EventType: RenameKey Image: *\072wiof7.exe | Source: IOC filename 072wiof7.exe  
[IOC] EventType: RenameKey Image: *\k0d649u.exe | Source: IOC filename k0d649u.exe  
[IOC] EventType: RenameKey Image: *\2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat | Source: IOC filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType: RenameKey Image: *\2qfguc.exe | Source: IOC filename 2qfguc.exe  
[IOC] EventType: RenameKey Image: *\7hhel.exe | Source: IOC filename 7hhel.exe  
[IOC] EventType: RenameKey Image: *\3ctjhm3.exe | Source: IOC filename 3ctjhm3.exe  
[IOC] EventType: RenameKey Image: *\2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat | Source: IOC filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akir…  
[IOC] EventType: RenameKey Image: *\bjiw49.exe | Source: IOC filename bjiw49.exe  
[IOC] EventType: RenameKey Image: *\7l73h.exe | Source: IOC filename 7l73h.exe  
[IOC] EventType: RenameKey Image: *\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat | Source: IOC filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_ak…  
[IOC] EventType: RenameKey Image: *\0m6m882x2.exe | Source: IOC filename 0m6m882x2.exe  
[IOC] EventType: RenameKey Image: *\inc.exe | Source: IOC filename inc.exe  
[IOC] EventType: RenameKey Image: *\61pd6n3t.exe | Source: IOC filename 61pd6n3t.exe  
[IOC] EventType: RenameKey Image: *\mk1yd.exe | Source: IOC filename mk1yd.exe  
[IOC] EventType: RenameKey Image: *\a3mnw9.exe | Source: IOC filename a3mnw9.exe  
[IOC] EventType: RenameKey Image: *\win.bin | Source: IOC filename win.bin  
[IOC] EventType: RenameKey Image: *\vw06lg0y.exe | Source: IOC filename vw06lg0y.exe  
[IOC] EventType: RenameKey Image: *\qgp2s6z.exe | Source: IOC filename qgp2s6z.exe  
[IOC] EventType: RenameKey Image: *\tt24n8xsl.exe | Source: IOC filename tt24n8xsl.exe  

[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\Software\Microsoft\Windows\CurrentVersion\Run* NewName: * | Source: T1112 – Registry modifications for persistence (Run/RunOnce keys)  

[BEHAVIOR] EventType: RenameKey Image: * TargetObject: HKLM\SYSTEM\CurrentControlSet\Services* NewName: * | Source: T1569.002 – Service execution/persistence via service registry keys  

[DERIVED] EventType: RenameKey Image: * TargetObject: * NewName: * | Source: T1219 – Remote access tools may rename registry keys/values as part of installing or maintaining covert agents (e.g., to hide persistence artifacts)  