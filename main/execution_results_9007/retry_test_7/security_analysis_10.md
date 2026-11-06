[IOC] SourceImage = x86_64-unknown-linux-esxi.elf, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: x86_64-unknown-linux-esxi.elf  
[IOC] SourceImage = h3odp7l2u.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: h3odp7l2u.exe  
[IOC] SourceImage = hi9lezv.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: hi9lezv.exe  
[IOC] SourceImage = 072wiof7.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 072wiof7.exe  
[IOC] SourceImage = k0d649u.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: k0d649u.exe  
[IOC] SourceImage = 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] SourceImage = 2qfguc.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 2qfguc.exe  
[IOC] SourceImage = 7hhel.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 7hhel.exe  
[IOC] SourceImage = 3ctjhm3.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 3ctjhm3.exe  
[IOC] SourceImage = 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] SourceImage = bjiw49.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: bjiw49.exe  
[IOC] SourceImage = 7l73h.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 7l73h.exe  
[IOC] SourceImage = 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] SourceImage = 0m6m882x2.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 0m6m882x2.exe  
[IOC] SourceImage = inc.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: inc.exe  
[IOC] SourceImage = 61pd6n3t.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: 61pd6n3t.exe  
[IOC] SourceImage = mk1yd.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: mk1yd.exe  
[IOC] SourceImage = a3mnw9.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: a3mnw9.exe  
[IOC] SourceImage = win.bin, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: win.bin  
[IOC] SourceImage = vw06lg0y.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: vw06lg0y.exe  
[IOC] SourceImage = qgp2s6z.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: qgp2s6z.exe  
[IOC] SourceImage = tt24n8xsl.exe, TargetImage = lsass.exe, GrantedAccess contains 0x1F0FFF (full access) | Source: tt24n8xsl.exe  

[BEHAVIOR] Any process (excluding known security tools) opening lsass.exe with GrantedAccess ≥ 0x1F0FFF (full access) | Source: T1003 (Credential Dumping) – AN0648  

[DERIVED] Any process opening another process of the same image (e.g., self‑unpacking loaders) with GrantedAccess that includes PROCESS_CREATE_THREAD (0x0002) and PROCESS_VM_WRITE (0x0020), indicative of in‑memory unpacking or code injection typical of T1027.002 (Software Packing) | Source: T1027.002  

---  

**Explanation of omitted IoCs:**  
All listed file names were considered as potential SourceImage values for LSASS access monitoring because their execution is a plausible precursor to credential dumping (T1003). No additional IoCs were omitted; every provided filename appears in at least one recommendation.