[IOC] EventType: RenameKey, Image: x86_64-unknown-linux-esxi.elf, TargetObject: *, NewName: * | Source: IOC filename x86_64-unknown-linux-esxi.elf  
[IOC] EventType: RenameKey, Image: h3odp7l2u.exe, TargetObject: *, NewName: * | Source: IOC filename h3odp7l2u.exe  
[IOC] EventType: RenameKey, Image: hi9lezv.exe, TargetObject: *, NewName: * | Source: IOC filename hi9lezv.exe  
[IOC] EventType: RenameKey, Image: 072wiof7.exe, TargetObject: *, NewName: * | Source: IOC filename 072wiof7.exe  
[IOC] EventType: RenameKey, Image: k0d649u.exe, TargetObject: *, NewName: * | Source: IOC filename k0d649u.exe  
[IOC] EventType: RenameKey, Image: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, TargetObject: *, NewName: * | Source: IOC filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType: RenameKey, Image: 2qfguc.exe, TargetObject: *, NewName: * | Source: IOC filename 2qfguc.exe  
[IOC] EventType: RenameKey, Image: 7hhel.exe, TargetObject: *, NewName: * | Source: IOC filename 7hhel.exe  
[IOC] EventType: RenameKey, Image: 3ctjhm3.exe, TargetObject: *, NewName: * | Source: IOC filename 3ctjhm3.exe  
[IOC] EventType: RenameKey, Image: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, TargetObject: *, NewName: * | Source: IOC filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType: RenameKey, Image: bjiw49.exe, TargetObject: *, NewName: * | Source: IOC filename bjiw49.exe  
[IOC] EventType: RenameKey, Image: 7l73h.exe, TargetObject: *, NewName: * | Source: IOC filename 7l73h.exe  
[IOC] EventType: RenameKey, Image: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, TargetObject: *, NewName: * | Source: IOC filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType: RenameKey, Image: 0m6m882x2.exe, TargetObject: *, NewName: * | Source: IOC filename 0m6m882x2.exe  
[IOC] EventType: RenameKey, Image: inc.exe, TargetObject: *, NewName: * | Source: IOC filename inc.exe  
[IOC] EventType: RenameKey, Image: 61pd6n3t.exe, TargetObject: *, NewName: * | Source: IOC filename 61pd6n3t.exe  
[IOC] EventType: RenameKey, Image: mk1yd.exe, TargetObject: *, NewName: * | Source: IOC filename mk1yd.exe  
[IOC] EventType: RenameKey, Image: a3mnw9.exe, TargetObject: *, NewName: * | Source: IOC filename a3mnw9.exe  
[IOC] EventType: RenameKey, Image: win.bin, TargetObject: *, NewName: * | Source: IOC filename win.bin  
[IOC] EventType: RenameKey, Image: vw06lg0y.exe, TargetObject: *, NewName: * | Source: IOC filename vw06lg0y.exe  
[IOC] EventType: RenameKey, Image: qgp2s6z.exe, TargetObject: *, NewName: * | Source: IOC filename qgp2s6z.exe  
[IOC] EventType: RenameKey, Image: tt24n8xsl.exe, TargetObject: *, NewName: * | Source: IOC filename tt24n8xsl.exe  

[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SYSTEM\CurrentControlSet\Services\*, NewName: * | Source: T1569.002 – Service Execution may rename service keys for persistence or covert execution.  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, NewName: * | Source: T1112 – Modify Registry for persistence (Run key).  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, NewName: * | Source: T1112 – Modify Registry for persistence (per‑user Run key).  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Recovery, NewName: * | Source: T1490 – Inhibit System Recovery may alter recovery configuration via registry renames.  
[BEHAVIOR] EventType: RenameKey, Image: *, TargetObject: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management, NewName: * | Source: T1112 – Registry modifications for defense evasion may include renaming memory‑management keys.  

**Explanation of omitted items**  
The ATT&CK technique T1219 (Remote Access Tools) is not represented in the recommendations because the provided context does not describe any registry‑key rename operations as a behavior of remote‑access tools. While remote access tools can modify the registry, the specific activity captured by Sysmon EventID 14 (renaming keys/values) is not mentioned for T1219, so no direct monitoring rule is derived from that technique. All other attack patterns (T1112, T1569.002, T1490) involve registry modifications that could include rename actions and are therefore included. No CVE descriptions reference registry‑key rename behavior, so none are incorporated.