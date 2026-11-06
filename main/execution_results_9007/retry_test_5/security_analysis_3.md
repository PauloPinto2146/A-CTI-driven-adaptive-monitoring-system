[IOC] Image = "h3odp7l2u.exe" | Source: IOC – filename h3odp7l2u.exe  
[IOC] Image = "hi9lezv.exe" | Source: IOC – filename hi9lezv.exe  
[IOC] Image = "072wiof7.exe" | Source: IOC – filename 072wiof7.exe  
[IOC] Image = "k0d649u.exe" | Source: IOC – filename k0d649u.exe  
[IOC] Image = "2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat.exe" | Source: IOC – filename 2026‑03‑08…  
[IOC] Image = "2qfguc.exe" | Source: IOC – filename 2qfguc.exe  
[IOC] Image = "7hhel.exe" | Source: IOC – filename 7hhel.exe  
[IOC] Image = "3ctjhm3.exe" | Source: IOC – filename 3ctjhm3.exe  
[IOC] Image = "2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat.exe" | Source: IOC – filename 2026‑04‑08…  
[IOC] Image = "bjiw49.exe" | Source: IOC – filename bjiw49.exe  
[IOC] Image = "7l73h.exe" | Source: IOC – filename 7l73h.exe  
[IOC] Image = "2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat.exe" | Source: IOC – filename 2026‑04‑11…  
[IOC] Image = "0m6m882x2.exe" | Source: IOC – filename 0m6m882x2.exe  
[IOC] Image = "inc.exe" | Source: IOC – filename inc.exe  
[IOC] Image = "61pd6n3t.exe" | Source: IOC – filename 61pd6n3t.exe  
[IOC] Image = "mk1yd.exe" | Source: IOC – filename mk1yd.exe  
[IOC] Image = "a3mnw9.exe" | Source: IOC – filename a3mnw9.exe  
[IOC] Image = "win.bin" | Source: IOC – filename win.bin  
[IOC] Image = "vw06lg0y.exe" | Source: IOC – filename vw06lg0y.exe  
[IOC] Image = "qgp2s6z.exe" | Source: IOC – filename qgp2s6z.exe  
[IOC] Image = "tt24n8xsl.exe" | Source: IOC – filename tt24n8xsl.exe  
[IOC] DestinationHostname = "incblog.su" | Source: IOC – domain incblog.su  
[IOC] DestinationHostname = "incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion" | Source: IOC – domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] DestinationHostname = "incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion" | Source: IOC – domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[BEHAVIOR] Protocol = TCP AND DestinationPort = 445 (standard SMB) | Source: T1021.002 – Remote System Shares  
[BEHAVIOR] Protocol = TCP AND DestinationPort = 3389 (RDP) | Source: T1021.001 – Remote Desktop Protocol  
[BEHAVIOR] Protocol = TCP AND DestinationPort = 443 (HTTPS) | Source: T1071 – Application Layer C2 / Web Service Exfiltration  
[BEHAVIOR] Protocol = TCP AND DestinationPort = 80 (HTTP) | Source: T1071 – Application Layer C2 / Web Service Exfiltration  
[BEHAVIOR] Protocol = UDP AND DestinationPort = 53 (DNS) | Source: T1071 – Application Layer C2 / DNS Tunneling  

[DERIVED] Image NOT IN {svchost.exe, lsass.exe, services.exe, explorer.exe, winlogon.exe} AND Protocol = TCP AND DestinationPort = 443 AND Initiated = true | Source: T1567 – Exfiltration Over Web Service (non‑standard processes making outbound HTTPS)  
[DERIVED] Protocol = UDP AND DestinationPort = 53 AND Image NOT IN {dns.exe, svchost.exe} | Source: T1557 – Adversary‑in‑the‑Middle (suspicious DNS queries from unusual processes)  
[DERIVED] Protocol = TCP AND DestinationPort IN {80,443,53,445,3389} AND Initiated = true AND Image IN {*.exe from the IOC list} | Source: T1190/T1219/T1569.002 – Malicious binaries establishing network beacons or remote‑access sessions.