[BEHAVIOR] Detect ProcessAccess events where TargetImage is *\lsass.exe and GrantedAccess contains high‑privilege flags such as PROCESS_VM_READ (0x0010), PROCESS_VM_WRITE (0x0020), PROCESS_QUERY_INFORMATION (0x0400) or full access (0x1F0FFF) | Source: T1003  

[BEHAVIOR] Detect ProcessAccess events where GrantedAccess includes PROCESS_CREATE_THREAD (0x0002) and PROCESS_VM_WRITE (0x0020) (or full access 0x1F0FFF) targeting executables outside the Windows system directories (TargetImage: *\*.exe, not under C:\Windows\System32) | Source: T1027.002  

[IOC] Monitor any process opening a process whose image matches **h3odp7l2u.exe** (TargetImage: *\h3odp7l2u.exe) with any access rights (GrantedAccess: *) | Source: h3odp7l2u.exe  

[IOC] Monitor any process opening a process whose image matches **hi9lezv.exe** (TargetImage: *\hi9lezv.exe) with any access rights (GrantedAccess: *) | Source: hi9lezv.exe  

[IOC] Monitor any process opening a process whose image matches **072wiof7.exe** (TargetImage: *\072wiof7.exe) with any access rights (GrantedAccess: *) | Source: 072wiof7.exe  

[IOC] Monitor any process opening a process whose image matches **k0d649u.exe** (TargetImage: *\k0d649u.exe) with any access rights (GrantedAccess: *) | Source: k0d649u.exe  

[IOC] Monitor any process opening a process whose image matches **2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat.exe** (TargetImage: *\2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat.exe) with any access rights (GrantedAccess: *) | Source: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat  

[IOC] Monitor any process opening a process whose image matches **2qfguc.exe** (TargetImage: *\2qfguc.exe) with any access rights (GrantedAccess: *) | Source: 2qfguc.exe  

[IOC] Monitor any process opening a process whose image matches **7hhel.exe** (TargetImage: *\7hhel.exe) with any access rights (GrantedAccess: *) | Source: 7hhel.exe  

[IOC] Monitor any process opening a process whose image matches **3ctjhm3.exe** (TargetImage: *\3ctjhm3.exe) with any access rights (GrantedAccess: *) | Source: 3ctjhm3.exe  

[IOC] Monitor any process opening a process whose image matches **2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat.exe** (TargetImage: *\2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat.exe) with any access rights (GrantedAccess: *) | Source: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat  

[IOC] Monitor any process opening a process whose image matches **bjiw49.exe** (TargetImage: *\bjiw49.exe) with any access rights (GrantedAccess: *) | Source: bjiw49.exe  

[IOC] Monitor any process opening a process whose image matches **7l73h.exe** (TargetImage: *\7l73h.exe) with any access rights (GrantedAccess: *) | Source: 7l73h.exe  

[IOC] Monitor any process opening a process whose image matches **2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat.exe** (TargetImage: *\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat.exe) with any access rights (GrantedAccess: *) | Source: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat  

[IOC] Monitor any process opening a process whose image matches **0m6m882x2.exe** (TargetImage: *\0m6m882x2.exe) with any access rights (GrantedAccess: *) | Source: 0m6m882x2.exe  

[IOC] Monitor any process opening a process whose image matches **inc.exe** (TargetImage: *\inc.exe) with any access rights (GrantedAccess: *) | Source: inc.exe  

[IOC] Monitor any process opening a process whose image matches **61pd6n3t.exe** (TargetImage: *\61pd6n3t.exe) with any access rights (GrantedAccess: *) | Source: 61pd6n3t.exe  

[IOC] Monitor any process opening a process whose image matches **mk1yd.exe** (TargetImage: *\mk1yd.exe) with any access rights (GrantedAccess: *) | Source: mk1yd.exe  

[IOC] Monitor any process opening a process whose image matches **a3mnw9.exe** (TargetImage: *\a3mnw9.exe) with any access rights (GrantedAccess: *) | Source: a3mnw9.exe  

[IOC] Monitor any process opening a process whose image matches **vw06lg0y.exe** (TargetImage: *\vw06lg0y.exe) with any access rights (GrantedAccess: *) | Source: vw06lg0y.exe  

[IOC] Monitor any process opening a process whose image matches **qgp2s6z.exe** (TargetImage: *\qgp2s6z.exe) with any access rights (GrantedAccess: *) | Source: qgp2s6z.exe  

[IOC] Monitor any process opening a process whose image matches **tt24n8xsl.exe** (TargetImage: *\tt24n8xsl.exe) with any access rights (GrantedAccess: *) | Source: tt24n8xsl.exe  

**Explanation of omitted IoCs**: The file **x86_64-unknown-linux-esxi.elf** is a Linux ELF binary and therefore cannot be instantiated as a Windows process observable by Sysmon Event 10; it is excluded. The entry **win.bin** lacks an executable extension and there is no evidence it appears as a Windows process image, so it is also omitted from ProcessAccess monitoring.