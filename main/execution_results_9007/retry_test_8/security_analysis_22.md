[IOC] Image ends with “x86_64-unknown-linux-esxi.elf” – any DNS query | Source: IOC filename x86_64-unknown-linux-esxi.elf  
[IOC] Image ends with “h3odp7l2u.exe” – any DNS query | Source: IOC filename h3odp7l2u.exe  
[IOC] Image ends with “hi9lezv.exe” – any DNS query | Source: IOC filename hi9lezv.exe  
[IOC] Image ends with “072wiof7.exe” – any DNS query | Source: IOC filename 072wiof7.exe  
[IOC] Image ends with “k0d649u.exe” – any DNS query | Source: IOC filename k0d649u.exe  
[IOC] Image ends with “2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat” – any DNS query | Source: IOC filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat  
[IOC] Image ends with “2qfguc.exe” – any DNS query | Source: IOC filename 2qfguc.exe  
[IOC] Image ends with “7hhel.exe” – any DNS query | Source: IOC filename 7hhel.exe  
[IOC] Image ends with “3ctjhm3.exe” – any DNS query | Source: IOC filename 3ctjhm3.exe  
[IOC] Image ends with “2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat” – any DNS query | Source: IOC filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat  
[IOC] Image ends with “bjiw49.exe” – any DNS query | Source: IOC filename bjiw49.exe  
[IOC] Image ends with “7l73h.exe” – any DNS query | Source: IOC filename 7l73h.exe  
[IOC] Image ends with “2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat” – any DNS query | Source: IOC filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat  
[IOC] Image ends with “0m6m882x2.exe” – any DNS query | Source: IOC filename 0m6m882x2.exe  
[IOC] Image ends with “inc.exe” – any DNS query | Source: IOC filename inc.exe  
[IOC] Image ends with “61pd6n3t.exe” – any DNS query | Source: IOC filename 61pd6n3t.exe  
[IOC] Image ends with “mk1yd.exe” – any DNS query | Source: IOC filename mk1yd.exe  
[IOC] Image ends with “a3mnw9.exe” – any DNS query | Source: IOC filename a3mnw9.exe  
[IOC] Image ends with “win.bin” – any DNS query | Source: IOC filename win.bin  
[IOC] Image ends with “vw06lg0y.exe” – any DNS query | Source: IOC filename vw06lg0y.exe  
[IOC] Image ends with “qgp2s6z.exe” – any DNS query | Source: IOC filename qgp2s6z.exe  
[IOC] Image ends with “tt24n8xsl.exe” – any DNS query | Source: IOC filename tt24n8xsl.exe  
[IOC] QueryName equals “incblog.su” – any process image | Source: IOC domain incblog.su  
[IOC] QueryName equals “incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion” – any process image | Source: IOC domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] QueryName equals “incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion” – any process image | Source: IOC domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[BEHAVIOR] DNS queries with QueryStatus indicating failure (e.g., NXDOMAIN, SERVFAIL) from any process – possible DNS‑poisoning or AiTM activity | Source: T1557  
[BEHAVIOR] More than 100 DNS queries from a single Image within a 60‑second window – indicative of DNS‑based command‑and‑control channel | Source: T1071  
[BEHAVIOR] DNS queries where QueryName length > 50 characters or containing high‑entropy (base64‑like) sub‑strings – potential data‑exfiltration over DNS | Source: T1567   (derived from exfiltration over web service/Covert channels)  