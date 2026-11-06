[IOC] Image equals *\h3odp7l2u.exe* | Source: filename h3odp7l2u.exe  
[IOC] Image equals *\inc.exe* | Source: filename inc.exe  
[IOC] Image equals *\2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat.exe* | Source: filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image equals *\2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat.exe* | Source: filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image equals *\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat.exe* | Source: filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image equals *\x86_64-unknown-linux-esxi.elf* | Source: filename x86_64-unknown-linux-esxi.elf  
[IOC] Image equals *\hi9lezv.exe* | Source: filename hi9lezv.exe  
[IOC] Image equals *\072wiof7.exe* | Source: filename 072wiof7.exe  
[IOC] Image equals *\k0d649u.exe* | Source: filename k0d649u.exe  
[IOC] Image equals *\2qfguc.exe* | Source: filename 2qfguc.exe  
[IOC] Image equals *\7hhel.exe* | Source: filename 7hhel.exe  
[IOC] Image equals *\3ctjhm3.exe* | Source: filename 3ctjhm3.exe  
[IOC] Image equals *\bjiw49.exe* | Source: filename bjiw49.exe  
[IOC] Image equals *\7l73h.exe* | Source: filename 7l73h.exe  
[IOC] Image equals *\0m6m882x2.exe* | Source: filename 0m6m882x2.exe  
[IOC] Image equals *\61pd6n3t.exe* | Source: filename 61pd6n3t.exe  
[IOC] Image equals *\mk1yd.exe* | Source: filename mk1yd.exe  
[IOC] Image equals *\a3mnw9.exe* | Source: filename a3mnw9.exe  
[IOC] Image equals *\win.bin* | Source: filename win.bin  
[IOC] Image equals *\vw06lg0y.exe* | Source: filename vw06lg0y.exe  
[IOC] Image equals *\qgp2s6z.exe* | Source: filename qgp2s6z.exe  
[IOC] Image equals *\tt24n8xsl.exe* | Source: filename tt24n8xsl.exe  

[IOC] DestinationHostname equals incblog.su | Source: domain incblog.su  
[IOC] DestinationHostname equals incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion | Source: domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] DestinationHostname equals incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion | Source: domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[BEHAVIOR] Protocol = SMB and DestinationPort = 445 | Source: T1021.002  
[BEHAVIOR] Protocol = SMB and DestinationPort = 139 | Source: T1021.002  

[BEHAVIOR] Protocol = RDP and DestinationPort = 3389 | Source: T1021.001  

[BEHAVIOR] Protocol = TCP and DestinationPort = 53 | Source: T1557 (DNS/ARP poisoning for MITM)  

[DERIVED] Protocol = TCP and DestinationPort in {80,443} and DestinationHostname is external (not internal) | Source: T1567 (Exfiltration Over Web Service)  

[DERIVED] Initiated = true and Image matches any known malicious filename (see IOC list) and DestinationPort is external (non‑local) | Source: T1219 (Remote Access Tools)  

[DERIVED] Initiated = true and Image = *\sc.exe* or *\net.exe* or *\services.exe* and DestinationPort = any and ServiceBinaryAllowlist not matched | Source: T1569.002 (Service Execution)  