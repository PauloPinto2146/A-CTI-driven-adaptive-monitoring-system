[IOC] EventType=RenameKey, Image=*\\x86_64-unknown-linux-esxi.elf, TargetObject=*, NewName=* | Source: IOC x86_64-unknown-linux-esxi.elf  
[IOC] EventType=RenameKey, Image=*\\h3odp7l2u.exe, TargetObject=*, NewName=* | Source: IOC h3odp7l2u.exe  
[IOC] EventType=RenameKey, Image=*\\hi9lezv.exe, TargetObject=*, NewName=* | Source: IOC hi9lezv.exe  
[IOC] EventType=RenameKey, Image=*\\072wiof7.exe, TargetObject=*, NewName=* | Source: IOC 072wiof7.exe  
[IOC] EventType=RenameKey, Image=*\\k0d649u.exe, TargetObject=*, NewName=* | Source: IOC k0d649u.exe  
[IOC] EventType=RenameKey, Image=*\\2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, TargetObject=*, NewName=* | Source: IOC 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType=RenameKey, Image=*\\2qfguc.exe, TargetObject=*, NewName=* | Source: IOC 2qfguc.exe  
[IOC] EventType=RenameKey, Image=*\\7hhel.exe, TargetObject=*, NewName=* | Source: IOC 7hhel.exe  
[IOC] EventType=RenameKey, Image=*\\3ctjhm3.exe, TargetObject=*, NewName=* | Source: IOC 3ctjhm3.exe  
[IOC] EventType=RenameKey, Image=*\\2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, TargetObject=*, NewName=* | Source: IOC 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType=RenameKey, Image=*\\bjiw49.exe, TargetObject=*, NewName=* | Source: IOC bjiw49.exe  
[IOC] EventType=RenameKey, Image=*\\7l73h.exe, TargetObject=*, NewName=* | Source: IOC 7l73h.exe  
[IOC] EventType=RenameKey, Image=*\\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, TargetObject=*, NewName=* | Source: IOC 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] EventType=RenameKey, Image=*\\0m6m882x2.exe, TargetObject=*, NewName=* | Source: IOC 0m6m882x2.exe  
[IOC] EventType=RenameKey, Image=*\\inc.exe, TargetObject=*, NewName=* | Source: IOC inc.exe  
[IOC] EventType=RenameKey, Image=*\\61pd6n3t.exe, TargetObject=*, NewName=* | Source: IOC 61pd6n3t.exe  
[IOC] EventType=RenameKey, Image=*\\mk1yd.exe, TargetObject=*, NewName=* | Source: IOC mk1yd.exe  
[IOC] EventType=RenameKey, Image=*\\a3mnw9.exe, TargetObject=*, NewName=* | Source: IOC a3mnw9.exe  
[IOC] EventType=RenameKey, Image=*\\win.bin, TargetObject=*, NewName=* | Source: IOC win.bin  
[IOC] EventType=RenameKey, Image=*\\vw06lg0y.exe, TargetObject=*, NewName=* | Source: IOC vw06lg0y.exe  
[IOC] EventType=RenameKey, Image=*\\qgp2s6z.exe, TargetObject=*, NewName=* | Source: IOC qgp2s6z.exe  
[IOC] EventType=RenameKey, Image=*\\tt24n8xsl.exe, TargetObject=*, NewName=* | Source: IOC tt24n8xsl.exe  

[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*, NewName=* | Source: T1112  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SYSTEM\CurrentControlSet\Services\*, NewName=* | Source: T1569.002  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*, NewName=* | Source: T1112  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit, NewName=* | Source: T1112  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell, NewName=* | Source: T1112  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*, NewName=* | Source: T1112  
[BEHAVIOR] EventType=RenameKey, Image=*, TargetObject=HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode, NewName=* | Source: T1112  

NO RECOMMENDATIONS (for CVE‑2023‑3519, CVE‑2023‑48788, CVE‑2024‑57727, CVE‑2025‑5777 – these vulnerabilities do not involve registry rename operations)