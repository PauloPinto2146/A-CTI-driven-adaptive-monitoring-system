[BEHAVIOR] Monitor any process opening **lsass.exe** with `PROCESS_VM_READ` (0x0010) or `PROCESS_VM_WRITE` (0x0020) or full access (0x1F0FFF) | Source: T1003 – Credential Dumping  

[IOC] SourceImage = *\<any path>\h3odp7l2u.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: h3odp7l2u.exe  

[IOC] SourceImage = *\<any path>\hi9lezv.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: hi9lezv.exe  

[IOC] SourceImage = *\<any path>\072wiof7.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 072wiof7.exe  

[IOC] SourceImage = *\<any path>\k0d649u.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: k0d649u.exe  

[IOC] SourceImage = *\<any path>\2qfguc.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 2qfguc.exe  

[IOC] SourceImage = *\<any path>\7hhel.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 7hhel.exe  

[IOC] SourceImage = *\<any path>\3ctjhm3.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 3ctjhm3.exe  

[IOC] SourceImage = *\<any path>\bjiw49.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: bjiw49.exe  

[IOC] SourceImage = *\<any path>\7l73h.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 7l73h.exe  

[IOC] SourceImage = *\<any path>\0m6m882x2.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 0m6m882x2.exe  

[IOC] SourceImage = *\<any path>\inc.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: inc.exe  

[IOC] SourceImage = *\<any path>\61pd6n3t.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 61pd6n3t.exe  

[IOC] SourceImage = *\<any path>\mk1yd.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: mk1yd.exe  

[IOC] SourceImage = *\<any path>\a3mnw9.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: a3mnw9.exe  

[IOC] SourceImage = *\<any path>\vw06lg0y.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: vw06lg0y.exe  

[IOC] SourceImage = *\<any path>\qgp2s6z.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: qgp2s6z.exe  

[IOC] SourceImage = *\<any path>\tt24n8xsl.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: tt24n8xsl.exe  

[IOC] SourceImage = *\<any path>\2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat  

[IOC] SourceImage = *\<any path>\2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat  

[IOC] SourceImage = *\<any path>\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat.exe TargetImage = *\<any path>\lsass.exe GrantedAccess = 0x1F0FFF CallTrace = kernel32!OpenProcess+0x??, ntdll!NtOpenProcess+0x?? | Source: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat  

**Explanation for omitted IoCs:**  

- `x86_64-unknown-linux-esxi.elf` is a Linux ELF binary; Sysmon on Windows cannot observe it, so it cannot be captured via EventID 10.  
- `win.bin` and other non‑`.exe` entries (e.g., `win.bin`) are not executable processes on Windows and therefore will not generate a Process Access event.  
- The long filenames prefixed with dates (`2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat`, etc.) are metadata/archival artifacts rather than running executables; without evidence they are executed as processes, they are outside the scope of EventID 10 monitoring.  

NO RECOMMENDATIONS (for any remaining indicators that cannot be observed).