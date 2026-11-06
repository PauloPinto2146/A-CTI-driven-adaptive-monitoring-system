[IOC] SourceImage: h3odp7l2u.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: h3odp7l2u.exe  
[IOC] SourceImage: hi9lezv.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: hi9lezv.exe  
[IOC] SourceImage: 072wiof7.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 072wiof7.exe  
[IOC] SourceImage: k0d649u.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: k0d649u.exe  
[IOC] SourceImage: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] SourceImage: 2qfguc.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 2qfguc.exe  
[IOC] SourceImage: 7hhel.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 7hhel.exe  
[IOC] SourceImage: 3ctjhm3.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 3ctjhm3.exe  
[IOC] SourceImage: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] SourceImage: bjiw49.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: bjiw49.exe  
[IOC] SourceImage: 7l73h.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 7l73h.exe  
[IOC] SourceImage: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] SourceImage: 0m6m882x2.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 0m6m882x2.exe  
[IOC] SourceImage: inc.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: inc.exe  
[IOC] SourceImage: 61pd6n3t.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: 61pd6n3t.exe  
[IOC] SourceImage: mk1yd.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: mk1yd.exe  
[IOC] SourceImage: a3mnw9.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: a3mnw9.exe  
[IOC] SourceImage: vw06lg0y.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: vw06lg0y.exe  
[IOC] SourceImage: qgp2s6z.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: qgp2s6z.exe  
[IOC] SourceImage: tt24n8xsl.exe, TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF, CallTrace: any | Source: tt24n8xsl.exe  

[BEHAVIOR] SourceImage: * (any process not whitelisted), TargetImage: C:\Windows\System32\lsass.exe, GrantedAccess: 0x1F0FFF (full access), CallTrace: any | Source: T1003  

[BEHAVIOR] SourceImage: * (any suspicious loader or droppable executable), TargetImage: *.exe, GrantedAccess: 0x0000002A (PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION), CallTrace: any | Source: T1027.002  

--- Omitted Indicators Explanation ---  
- x86_64-unknown-linux-esxi.elf: Linux ELF binary; Sysmon on Windows only logs Windows PE processes, so Event ID 10 cannot capture this file as a source image.  
- win.bin: Not a PE executable (binary data); therefore it will not appear as a process image in Windows Sysmon logs and cannot be observed via Event ID 10.  