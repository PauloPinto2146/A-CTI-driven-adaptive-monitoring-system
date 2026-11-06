[IOC] Image: *, TargetFilename: x86_64-unknown-linux-esxi.elf, CreationUtcTime: * | Source: x86_64-unknown-linux-esxi.elf  
[IOC] Image: *, TargetFilename: h3odp7l2u.exe, CreationUtcTime: * | Source: h3odp7l2u.exe  
[IOC] Image: *, TargetFilename: hi9lezv.exe, CreationUtcTime: * | Source: hi9lezv.exe  
[IOC] Image: *, TargetFilename: 072wiof7.exe, CreationUtcTime: * | Source: 072wiof7.exe  
[IOC] Image: *, TargetFilename: k0d649u.exe, CreationUtcTime: * | Source: k0d649u.exe  
[IOC] Image: *, TargetFilename: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: 2qfguc.exe, CreationUtcTime: * | Source: 2qfguc.exe  
[IOC] Image: *, TargetFilename: 7hhel.exe, CreationUtcTime: * | Source: 7hhel.exe  
[IOC] Image: *, TargetFilename: 3ctjhm3.exe, CreationUtcTime: * | Source: 3ctjhm3.exe  
[IOC] Image: *, TargetFilename: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: bjiw49.exe, CreationUtcTime: * | Source: bjiw49.exe  
[IOC] Image: *, TargetFilename: 7l73h.exe, CreationUtcTime: * | Source: 7l73h.exe  
[IOC] Image: *, TargetFilename: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: 0m6m882x2.exe, CreationUtcTime: * | Source: 0m6m882x2.exe  
[IOC] Image: *, TargetFilename: inc.exe, CreationUtcTime: * | Source: inc.exe  
[IOC] Image: *, TargetFilename: 61pd6n3t.exe, CreationUtcTime: * | Source: 61pd6n3t.exe  
[IOC] Image: *, TargetFilename: mk1yd.exe, CreationUtcTime: * | Source: mk1yd.exe  
[IOC] Image: *, TargetFilename: a3mnw9.exe, CreationUtcTime: * | Source: a3mnw9.exe  
[IOC] Image: *, TargetFilename: win.bin, CreationUtcTime: * | Source: win.bin  
[IOC] Image: *, TargetFilename: vw06lg0y.exe, CreationUtcTime: * | Source: vw06lg0y.exe  
[IOC] Image: *, TargetFilename: qgp2s6z.exe, CreationUtcTime: * | Source: qgp2s6z.exe  
[IOC] Image: *, TargetFilename: tt24n8xsl.exe, CreationUtcTime: * | Source: tt24n8xsl.exe  

[BEHAVIOR] Image: *, TargetFilename: *\Startup\*, CreationUtcTime: * | Source: T1219 (Remote Access Tools) – monitor file creation in autostart locations used for persistence.  

[BEHAVIOR] Image: *, TargetFilename: *\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*, CreationUtcTime: * | Source: T1219 (Remote Access Tools) – monitor creation in the per‑user Startup folder.  

[BEHAVIOR] Image: *, TargetFilename: *\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*, CreationUtcTime: * | Source: T1219 (Remote Access Tools) – monitor creation in the common startup folder.  

[BEHAVIOR] Image: *, TargetFilename: *\Temp\*, CreationUtcTime: * | Source: T1219 (Remote Access Tools) – monitor drops in temporary directories.  

[BEHAVIOR] Image: *, TargetFilename: *\Downloads\*, CreationUtcTime: * | Source: T1219 (Remote Access Tools) – monitor drops in user download directories.  

[DERIVED] Image: *, TargetFilename: *, CreationUtcTime: * | Source: T1486 (Data Encrypted for Impact) – flag high‑frequency file creation (e.g., >100 files within a 1‑minute window) indicative of ransomware encryption activity.  