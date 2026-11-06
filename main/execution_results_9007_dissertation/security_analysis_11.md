[IOC] Image: *, TargetFilename: x86_64-unknown-linux-esxi.elf, CreationUtcTime: * | Source: IOC x86_64-unknown-linux-esxi.elf  
[IOC] Image: *, TargetFilename: h3odp7l2u.exe, CreationUtcTime: * | Source: IOC h3odp7l2u.exe  
[IOC] Image: *, TargetFilename: hi9lezv.exe, CreationUtcTime: * | Source: IOC hi9lezv.exe  
[IOC] Image: *, TargetFilename: 072wiof7.exe, CreationUtcTime: * | Source: IOC 072wiof7.exe  
[IOC] Image: *, TargetFilename: k0d649u.exe, CreationUtcTime: * | Source: IOC k0d649u.exe  
[IOC] Image: *, TargetFilename: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: IOC 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: 2qfguc.exe, CreationUtcTime: * | Source: IOC 2qfguc.exe  
[IOC] Image: *, TargetFilename: 7hhel.exe, CreationUtcTime: * | Source: IOC 7hhel.exe  
[IOC] Image: *, TargetFilename: 3ctjhm3.exe, CreationUtcTime: * | Source: IOC 3ctjhm3.exe  
[IOC] Image: *, TargetFilename: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: IOC 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: bjiw49.exe, CreationUtcTime: * | Source: IOC bjiw49.exe  
[IOC] Image: *, TargetFilename: 7l73h.exe, CreationUtcTime: * | Source: IOC 7l73h.exe  
[IOC] Image: *, TargetFilename: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: IOC 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: 0m6m882x2.exe, CreationUtcTime: * | Source: IOC 0m6m882x2.exe  
[IOC] Image: *, TargetFilename: inc.exe, CreationUtcTime: * | Source: IOC inc.exe  
[IOC] Image: *, TargetFilename: 61pd6n3t.exe, CreationUtcTime: * | Source: IOC 61pd6n3t.exe  
[IOC] Image: *, TargetFilename: mk1yd.exe, CreationUtcTime: * | Source: IOC mk1yd.exe  
[IOC] Image: *, TargetFilename: a3mnw9.exe, CreationUtcTime: * | Source: IOC a3mnw9.exe  
[IOC] Image: *, TargetFilename: win.bin, CreationUtcTime: * | Source: IOC win.bin  
[IOC] Image: *, TargetFilename: vw06lg0y.exe, CreationUtcTime: * | Source: IOC vw06lg0y.exe  
[IOC] Image: *, TargetFilename: qgp2s6z.exe, CreationUtcTime: * | Source: IOC qgp2s6z.exe  
[IOC] Image: *, TargetFilename: tt24n8xsl.exe, CreationUtcTime: * | Source: IOC tt24n8xsl.exe  

[BEHAVIOR] Image: *, TargetFilename: *\Downloads\*.exe, CreationUtcTime: * | Source: T1567  
[BEHAVIOR] Image: *, TargetFilename: *\Downloads\*.elf, CreationUtcTime: * | Source: T1567  
[BEHAVIOR] Image: *, TargetFilename: *\Temp\*.exe, CreationUtcTime: * | Source: T1567  
[BEHAVIOR] Image: *, TargetFilename: *\Temp\*.dll, CreationUtcTime: * | Source: T1567  
[BEHAVIOR] Image: *, TargetFilename: *\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*.exe, CreationUtcTime: * | Source: T1219  

[DERIVED] Image: *, TargetFilename: *\Windows\System32\*.exe, CreationUtcTime: * | Source: CVE-2023-3519  
[DERIVED] Image: *, TargetFilename: *\Windows\System32\*.dll, CreationUtcTime: * | Source: CVE-2023-3519  
[DERIVED] Image: *, TargetFilename: *\*.txt, CreationUtcTime: * | Source: T1486  
[DERIVED] Image: *, TargetFilename: *\*.lock, CreationUtcTime: * | Source: T1486  
[DERIVED] Image: *, TargetFilename: *\*.encrypted, CreationUtcTime: * | Source: T1486  