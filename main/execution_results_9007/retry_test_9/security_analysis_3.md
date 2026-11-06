[IOC] Image = “inc.exe” (any protocol, any destination) | Source: filename inc.exe  
[IOC] Image = “2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat” (any protocol, any destination) | Source: filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat  
[IOC] Image = “2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat” (any protocol, any destination) | Source: filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat  
[IOC] Image = “2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat” (any protocol, any destination) | Source: filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat  
[IOC] Image = “h3odp7l2u.exe” (any protocol, any destination) | Source: filename h3odp7l2u.exe  
[IOC] Image = “hi9lezv.exe” (any protocol, any destination) | Source: filename hi9lezv.exe  
[IOC] Image = “072wiof7.exe” (any protocol, any destination) | Source: filename 072wiof7.exe  
[IOC] Image = “k0d649u.exe” (any protocol, any destination) | Source: filename k0d649u.exe  
[IOC] Image = “2qfguc.exe” (any protocol, any destination) | Source: filename 2qfguc.exe  
[IOC] Image = “7hhel.exe” (any protocol, any destination) | Source: filename 7hhel.exe  
[IOC] Image = “3ctjhm3.exe” (any protocol, any destination) | Source: filename 3ctjhm3.exe  
[IOC] Image = “bjiw49.exe” (any protocol, any destination) | Source: filename bjiw49.exe  
[IOC] Image = “7l73h.exe” (any protocol, any destination) | Source: filename 7l73h.exe  
[IOC] Image = “0m6m882x2.exe” (any protocol, any destination) | Source: filename 0m6m882x2.exe  
[IOC] Image = “61pd6n3t.exe” (any protocol, any destination) | Source: filename 61pd6n3t.exe  
[IOC] Image = “mk1yd.exe” (any protocol, any destination) | Source: filename mk1yd.exe  
[IOC] Image = “a3mnw9.exe” (any protocol, any destination) | Source: filename a3mnw9.exe  
[IOC] Image = “win.bin” (any protocol, any destination) | Source: filename win.bin  
[IOC] Image = “vw06lg0y.exe” (any protocol, any destination) | Source: filename vw06lg0y.exe  
[IOC] Image = “qgp2s6z.exe” (any protocol, any destination) | Source: filename qgp2s6z.exe  
[IOC] Image = “tt24n8xsl.exe” (any protocol, any destination) | Source: filename tt24n8xsl.exe  
[IOC] DestinationHostname = “incblog.su” (any process, any protocol) | Source: domain incblog.su  
[IOC] DestinationHostname = “incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion” (any process, any protocol) | Source: domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] DestinationHostname = “incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion” (any process, any protocol) | Source: domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[BEHAVIOR] Protocol = UDP, DestinationPort = 53 (DNS) connections initiated by any process – indicative of DNS‑based C2 or AiTM activity | Source: T1557  
[BEHAVIOR] DestinationPort = 443, Protocol = TCP, Image not in typical web‑browser allowlist – high‑volume outbound HTTPS traffic possibly used for exfiltration over web services | Source: T1567  
[BEHAVIOR] DestinationPort = 80, Protocol = TCP, Image not in typical web‑browser allowlist – outbound HTTP traffic possibly used for C2 or data exfiltration | Source: T1071  
[BEHAVIOR] DestinationPort = 445, Protocol = TCP – SMB/Windows Admin Share connections (internal or external) suggest lateral movement via admin shares | Source: T1021.002  
[BEHAVIOR] DestinationPort = 139, Protocol = TCP – NetBIOS/SMB enumeration traffic indicative of remote system discovery | Source: T1018  
[BEHAVIOR] DestinationPort = 3389, Protocol = TCP – RDP connections (remote desktop) from any process, flag unusual initiators | Source: T1021.001  
[BEHAVIOR] Image = “sc.exe” OR Image = “services.exe” OR Image = “net.exe”, Initiated = true – service‑execution related processes that subsequently open network connections (service execution) | Source: T1569.002  
[DERIVED] Image = “powershell.exe”, DestinationPort in {80,443}, Initiated = true – PowerShell‑driven outbound web traffic often used for C2 over common application‑layer protocols | Source: T1071  
[DERIVED] Image = “wmic.exe” OR Image = “winrs.exe”, DestinationPort = 445, Initiated = true – remote execution tools leveraging SMB can create outbound connections for lateral movement | Source: T1569.002  