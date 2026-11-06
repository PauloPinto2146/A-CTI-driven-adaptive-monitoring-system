[IOC] Image: *, TargetFilename: x86_64-unknown-linux-esxi.elf, CreationUtcTime: * | Source: IOC filename x86_64-unknown-linux-esxi.elf  
[IOC] Image: *, TargetFilename: h3odp7l2u.exe, CreationUtcTime: * | Source: IOC filename h3odp7l2u.exe  
[IOC] Image: *, TargetFilename: hi9lezv.exe, CreationUtcTime: * | Source: IOC filename hi9lezv.exe  
[IOC] Image: *, TargetFilename: 072wiof7.exe, CreationUtcTime: * | Source: IOC filename 072wiof7.exe  
[IOC] Image: *, TargetFilename: k0d649u.exe, CreationUtcTime: * | Source: IOC filename k0d649u.exe  
[IOC] Image: *, TargetFilename: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: IOC filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: 2qfguc.exe, CreationUtcTime: * | Source: IOC filename 2qfguc.exe  
[IOC] Image: *, TargetFilename: 7hhel.exe, CreationUtcTime: * | Source: IOC filename 7hhel.exe  
[IOC] Image: *, TargetFilename: 3ctjhm3.exe, CreationUtcTime: * | Source: IOC filename 3ctjhm3.exe  
[IOC] Image: *, TargetFilename: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: IOC filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: bjiw49.exe, CreationUtcTime: * | Source: IOC filename bjiw49.exe  
[IOC] Image: *, TargetFilename: 7l73h.exe, CreationUtcTime: * | Source: IOC filename 7l73h.exe  
[IOC] Image: *, TargetFilename: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat, CreationUtcTime: * | Source: IOC filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *, TargetFilename: 0m6m882x2.exe, CreationUtcTime: * | Source: IOC filename 0m6m882x2.exe  
[IOC] Image: *, TargetFilename: inc.exe, CreationUtcTime: * | Source: IOC filename inc.exe  
[IOC] Image: *, TargetFilename: 61pd6n3t.exe, CreationUtcTime: * | Source: IOC filename 61pd6n3t.exe  
[IOC] Image: *, TargetFilename: mk1yd.exe, CreationUtcTime: * | Source: IOC filename mk1yd.exe  
[IOC] Image: *, TargetFilename: a3mnw9.exe, CreationUtcTime: * | Source: IOC filename a3mnw9.exe  
[IOC] Image: *, TargetFilename: win.bin, CreationUtcTime: * | Source: IOC filename win.bin  
[IOC] Image: *, TargetFilename: vw06lg0y.exe, CreationUtcTime: * | Source: IOC filename vw06lg0y.exe  
[IOC] Image: *, TargetFilename: qgp2s6z.exe, CreationUtcTime: * | Source: IOC filename qgp2s6z.exe  
[IOC] Image: *, TargetFilename: tt24n8xsl.exe, CreationUtcTime: * | Source: IOC filename tt24n8xsl.exe  

[BEHAVIOR] Image: *, TargetFilename: *\Startup\*, CreationUtcTime: * | Source: T1219 (Remote Access Tools may achieve persistence via autostart locations)  
[BEHAVIOR] Image: *, TargetFilename: *\AppData\Local\Temp\*, CreationUtcTime: * | Source: T1566 (Phishing payloads often drop malicious files in temporary directories)  
[BEHAVIOR] Image: *, TargetFilename: *\Downloads\*, CreationUtcTime: * | Source: T1567 (Exfiltration Over Web Service may involve staging data in download directories before upload)  
[BEHAVIOR] Image: *, TargetFilename: *.exe, CreationUtcTime: * | Source: T1486 (Ransomware frequently writes many new executable files during encryption phases)  
[BEHAVIOR] Image: *, TargetFilename: *.bin, CreationUtcTime: * | Source: T1486 (Ransomware may create binary payloads such as win.bin)  

[DERIVED] Image: *, TargetFilename: *random‑alphanumeric*.exe, CreationUtcTime: * | Source: Derived from multiple IOC filenames exhibiting short random alphanumeric names (e.g., 7hhel.exe, bjiw49.exe) indicating typical dropper naming conventions used in the observed campaign.  

[DERIVED] Image: *, TargetFilename: *.elf, CreationUtcTime: * | Source: Derived from the presence of a Linux ELF payload (x86_64-unknown-linux-esxi.elf) suggesting cross‑platform drop that may be written to disk on compromised Windows hosts via exploitation of CVE‑2023‑3519 or CVE‑2023‑48788.  

[DERIVED] Image: *, TargetFilename: *\* (any file), CreationUtcTime: * | Source: CVE‑2023‑3519 (Unauthenticated remote code execution can result in arbitrary file creation on the victim system)  

[DERIVED] Image: *, TargetFilename: *\* (any file), CreationUtcTime: * | Source: CVE‑2023‑48788 (SQL injection in FortiClientEMS may lead to deployment of malicious files)  

[DERIVED] Image: *, TargetFilename: *\* (any file), CreationUtcTime: * | Source: CVE‑2024‑57727 (Path‑traversal vulnerability can be leveraged to write files to arbitrary locations after downloading)  

[DERIVED] Image: *, TargetFilename: *\* (any file), CreationUtcTime: * | Source: CVE‑2025‑5777 (Memory overread may enable malicious payloads that drop files on the host)  