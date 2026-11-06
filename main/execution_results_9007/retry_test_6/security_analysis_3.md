[IOC] Image: *\inc.exe | Source: filename inc.exe  
[IOC] Image: *\h3odp7l2u.exe | Source: filename h3odp7l2u.exe  
[IOC] Image: *\hi9lezv.exe | Source: filename hi9lezv.exe  
[IOC] Image: *\072wiof7.exe | Source: filename 072wiof7.exe  
[IOC] Image: *\k0d649u.exe | Source: filename k0d649u.exe  
[IOC] Image: *\akira_cobalt-strike_glassworm_poet-rat.exe | Source: filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *\2qfguc.exe | Source: filename 2qfguc.exe  
[IOC] Image: *\7hhel.exe | Source: filename 7hhel.exe  
[IOC] Image: *\3ctjhm3.exe | Source: filename 3ctjhm3.exe  
[IOC] Image: *\akira_cobalt-strike_glassworm_poet-rat.exe | Source: filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *\bjiw49.exe | Source: filename bjiw49.exe  
[IOC] Image: *\7l73h.exe | Source: filename 7l73h.exe  
[IOC] Image: *\akira_cobalt-strike_glassworm_poet-rat.exe | Source: filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image: *\0m6m882x2.exe | Source: filename 0m6m882x2.exe  
[IOC] Image: *\inc.exe | Source: filename inc.exe  
[IOC] Image: *\61pd6n3t.exe | Source: filename 61pd6n3t.exe  
[IOC] Image: *\mk1yd.exe | Source: filename mk1yd.exe  
[IOC] Image: *\a3mnw9.exe | Source: filename a3mnw9.exe  
[IOC] Image: *\win.bin | Source: filename win.bin  
[IOC] Image: *\vw06lg0y.exe | Source: filename vw06lg0y.exe  
[IOC] Image: *\qgp2s6z.exe | Source: filename qgp2s6z.exe  
[IOC] Image: *\tt24n8xsl.exe | Source: filename tt24n8xsl.exe  
[IOC] DestinationHostname: incblog.su | Source: domain incblog.su  
[IOC] DestinationHostname: incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion | Source: domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] DestinationHostname: incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion | Source: domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[BEHAVIOR] Protocol: SMB, DestinationPort: 445, Initiated: true | Source: T1021.002  
[BEHAVIOR] Protocol: RDP, DestinationPort: 3389, Initiated: true | Source: T1021.001  
[BEHAVIOR] Protocol: DNS, Initiated: true | Source: T1071  
[BEHAVIOR] Protocol: HTTP, Initiated: true | Source: T1071  
[BEHAVIOR] Protocol: HTTPS, Initiated: true | Source: T1071  
[BEHAVIOR] Image: *\w3wp.exe, Protocol: HTTP, Initiated: true | Source: T1190  
[BEHAVIOR] Image: *\services.exe, Initiated: true | Source: T1569.002  
[BEHAVIOR] Image: *\net.exe, Protocol: TCP, Initiated: true | Source: T1018  
[DERIVED] Image: *\powershell.exe, Protocol: HTTPS, Initiated: true | Source: T1567  
[DERIVED] Protocol: TCP, DestinationPort: 0-1023, Initiated: true | Source: T1557 (monitor for possible ARP/DNS/LLMNR hijacking reflected in TCP/UDP traffic)  