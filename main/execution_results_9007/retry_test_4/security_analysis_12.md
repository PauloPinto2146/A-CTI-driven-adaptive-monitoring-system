[IOC] EventType=CreateKey Image=*\\h3odp7l2u.exe TargetObject=* | Source: h3odp7l2u.exe  
[IOC] EventType=DeleteKey Image=*\\h3odp7l2u.exe TargetObject=* | Source: h3odp7l2u.exe  

[IOC] EventType=CreateKey Image=*\\hi9lezv.exe TargetObject=* | Source: hi9lezv.exe  
[IOC] EventType=DeleteKey Image=*\\hi9lezv.exe TargetObject=* | Source: hi9lezv.exe  

[IOC] EventType=CreateKey Image=*\\072wiof7.exe TargetObject=* | Source: 072wiof7.exe  
[IOC] EventType=DeleteKey Image=*\\072wiof7.exe TargetObject=* | Source: 072wiof7.exe  

[IOC] EventType=CreateKey Image=*\\k0d649u.exe TargetObject=* | Source: k0d649u.exe  
[IOC] EventType=DeleteKey Image=*\\k0d649u.exe TargetObject=* | Source: k0d649u.exe  

[IOC] EventType=CreateKey Image=*\\2qfguc.exe TargetObject=* | Source: 2qfguc.exe  
[IOC] EventType=DeleteKey Image=*\\2qfguc.exe TargetObject=* | Source: 2qfguc.exe  

[IOC] EventType=CreateKey Image=*\\7hhel.exe TargetObject=* | Source: 7hhel.exe  
[IOC] EventType=DeleteKey Image=*\\7hhel.exe TargetObject=* | Source: 7hhel.exe  

[IOC] EventType=CreateKey Image=*\\3ctjhm3.exe TargetObject=* | Source: 3ctjhm3.exe  
[IOC] EventType=DeleteKey Image=*\\3ctjhm3.exe TargetObject=* | Source: 3ctjhm3.exe  

[IOC] EventType=CreateKey Image=*\\bjiw49.exe TargetObject=* | Source: bjiw49.exe  
[IOC] EventType=DeleteKey Image=*\\bjiw49.exe TargetObject=* | Source: bjiw49.exe  

[IOC] EventType=CreateKey Image=*\\7l73h.exe TargetObject=* | Source: 7l73h.exe  
[IOC] EventType=DeleteKey Image=*\\7l73h.exe TargetObject=* | Source: 7l73h.exe  

[IOC] EventType=CreateKey Image=*\\0m6m882x2.exe TargetObject=* | Source: 0m6m882x2.exe  
[IOC] EventType=DeleteKey Image=*\\0m6m882x2.exe TargetObject=* | Source: 0m6m882x2.exe  

[IOC] EventType=CreateKey Image=*\\inc.exe TargetObject=* | Source: inc.exe  
[IOC] EventType=DeleteKey Image=*\\inc.exe TargetObject=* | Source: inc.exe  

[IOC] EventType=CreateKey Image=*\\61pd6n3t.exe TargetObject=* | Source: 61pd6n3t.exe  
[IOC] EventType=DeleteKey Image=*\\61pd6n3t.exe TargetObject=* | Source: 61pd6n3t.exe  

[IOC] EventType=CreateKey Image=*\\mk1yd.exe TargetObject=* | Source: mk1yd.exe  
[IOC] EventType=DeleteKey Image=*\\mk1yd.exe TargetObject=* | Source: mk1yd.exe  

[IOC] EventType=CreateKey Image=*\\a3mnw9.exe TargetObject=* | Source: a3mnw9.exe  
[IOC] EventType=DeleteKey Image=*\\a3mnw9.exe TargetObject=* | Source: a3mnw9.exe  

[IOC] EventType=CreateKey Image=*\\win.bin TargetObject=* | Source: win.bin  
[IOC] EventType=DeleteKey Image=*\\win.bin TargetObject=* | Source: win.bin  

[IOC] EventType=CreateKey Image=*\\vw06lg0y.exe TargetObject=* | Source: vw06lg0y.exe  
[IOC] EventType=DeleteKey Image=*\\vw06lg0y.exe TargetObject=* | Source: vw06lg0y.exe  

[IOC] EventType=CreateKey Image=*\\qgp2s6z.exe TargetObject=* | Source: qgp2s6z.exe  
[IOC] EventType=DeleteKey Image=*\\qgp2s6z.exe TargetObject=* | Source: qgp2s6z.exe  

[IOC] EventType=CreateKey Image=*\\tt24n8xsl.exe TargetObject=* | Source: tt24n8xsl.exe  
[IOC] EventType=DeleteKey Image=*\\tt24n8xsl.exe TargetObject=* | Source: tt24n8xsl.exe  

[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  
[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  
[BEHAVIOR] EventType=CreateKey Image=* TargetObject=HKLM\System\CurrentControlSet\Services | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Source: T1219  
[BEHAVIOR] EventType=DeleteKey Image=* TargetObject=HKLM\System\CurrentControlSet\Services | Source: T1219  



*Explanation for omitted IoCs:*  
- **x86_64-unknown-linux-esxi.elf** is a Linux ELF binary; Sysmon EventID 12 records Windows registry activity, so changes made by this file cannot be observed on Windows hosts.  
- The three long‑named IOC strings that lack a typical Windows executable extension (e.g., `2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat`) do not explicitly represent a file path that could be captured as the `Image` field of a Windows process creating or deleting a registry key. Without a concrete executable name, they cannot be directly mapped to a Sysmon registry event and are therefore omitted.