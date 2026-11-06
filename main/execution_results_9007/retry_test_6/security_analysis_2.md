[IOC] Image: *; TargetFilename: *x86_64-unknown-linux-esxi.elf*; CreationUtcTime: * | Source: IOC filename x86_64-unknown-linux-esxi.elf  
[IOC] Image: *; TargetFilename: *h3odp7l2u.exe*; CreationUtcTime: * | Source: IOC filename h3odp7l2u.exe  
[IOC] Image: *; TargetFilename: *hi9lezv.exe*; CreationUtcTime: * | Source: IOC filename hi9lezv.exe  
[IOC] Image: *; TargetFilename: *072wiof7.exe*; CreationUtcTime: * | Source: IOC filename 072wiof7.exe  
[IOC] Image: *; TargetFilename: *k0d649u.exe*; CreationUtcTime: * | Source: IOC filename k0d649u.exe  
[IOC] Image: *; TargetFilename: *2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat*; CreationUtcTime: * | Source: IOC filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *; TargetFilename: *2qfguc.exe*; CreationUtcTime: * | Source: IOC filename 2qfguc.exe  
[IOC] Image: *; TargetFilename: *7hhel.exe*; CreationUtcTime: * | Source: IOC filename 7hhel.exe  
[IOC] Image: *; TargetFilename: *3ctjhm3.exe*; CreationUtcTime: * | Source: IOC filename 3ctjhm3.exe  
[IOC] Image: *; TargetFilename: *2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat*; CreationUtcTime: * | Source: IOC filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *; TargetFilename: *bjiw49.exe*; CreationUtcTime: * | Source: IOC filename bjiw49.exe  
[IOC] Image: *; TargetFilename: *7l73h.exe*; CreationUtcTime: * | Source: IOC filename 7l73h.exe  
[IOC] Image: *; TargetFilename: *2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat*; CreationUtcTime: * | Source: IOC filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *; TargetFilename: *0m6m882x2.exe*; CreationUtcTime: * | Source: IOC filename 0m6m882x2.exe  
[IOC] Image: *; TargetFilename: *inc.exe*; CreationUtcTime: * | Source: IOC filename inc.exe  
[IOC] Image: *; TargetFilename: *61pd6n3t.exe*; CreationUtcTime: * | Source: IOC filename 61pd6n3t.exe  
[IOC] Image: *; TargetFilename: *mk1yd.exe*; CreationUtcTime: * | Source: IOC filename mk1yd.exe  
[IOC] Image: *; TargetFilename: *a3mnw9.exe*; CreationUtcTime: * | Source: IOC filename a3mnw9.exe  
[IOC] Image: *; TargetFilename: *win.bin*; CreationUtcTime: * | Source: IOC filename win.bin  
[IOC] Image: *; TargetFilename: *vw06lg0y.exe*; CreationUtcTime: * | Source: IOC filename vw06lg0y.exe  
[IOC] Image: *; TargetFilename: *qgp2s6z.exe*; CreationUtcTime: * | Source: IOC filename qgp2s6z.exe  
[IOC] Image: *; TargetFilename: *tt24n8xsl.exe*; CreationUtcTime: * | Source: IOC filename tt24n8xsl.exe  

[BEHAVIOR] Image: *; TargetFilename: *\Users\*\Documents\*; CreationUtcTime: * | Source: T1486 (ransomware often modifies timestamps of files in user document folders to hide encryption activity)  
[BEHAVIOR] Image: *; TargetFilename: *\*\*\*; CreationUtcTime: * (where file extension is non‑standard or appears random, e.g., .xyz, .abc123) | Source: T1486 (ransomware commonly generates encrypted payloads with atypical extensions)  
[BEHAVIOR] Image: *; TargetFilename: *\Windows\System32\*; CreationUtcTime: * | Source: T1486 (adversaries may alter timestamps of system files to blend malicious components with OS files)  