[IOC] QueryName = incblog.su | Source: domain incblog.su  
[IOC] QueryName = incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion | Source: domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] QueryName = incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion | Source: domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[IOC] Image ends with x86_64-unknown-linux-esxi.elf | Source: filename x86_64-unknown-linux-esxi.elf  
[IOC] Image ends with h3odp7l2u.exe | Source: filename h3odp7l2u.exe  
[IOC] Image ends with hi9lezv.exe | Source: filename hi9lezv.exe  
[IOC] Image ends with 072wiof7.exe | Source: filename 072wiof7.exe  
[IOC] Image ends with k0d649u.exe | Source: filename k0d649u.exe  
[IOC] Image ends with 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat | Source: filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image ends with 2qfguc.exe | Source: filename 2qfguc.exe  
[IOC] Image ends with 7hhel.exe | Source: filename 7hhel.exe  
[IOC] Image ends with 3ctjhm3.exe | Source: filename 3ctjhm3.exe  
[IOC] Image ends with 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat | Source: filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image ends with bjiw49.exe | Source: filename bjiw49.exe  
[IOC] Image ends with 7l73h.exe | Source: filename 7l73h.exe  
[IOC] Image ends with 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat | Source: filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image ends with 0m6m882x2.exe | Source: filename 0m6m882x2.exe  
[IOC] Image ends with inc.exe | Source: filename inc.exe  
[IOC] Image ends with 61pd6n3t.exe | Source: filename 61pd6n3t.exe  
[IOC] Image ends with mk1yd.exe | Source: filename mk1yd.exe  
[IOC] Image ends with a3mnw9.exe | Source: filename a3mnw9.exe  
[IOC] Image ends with win.bin | Source: filename win.bin  
[IOC] Image ends with vw06lg0y.exe | Source: filename vw06lg0y.exe  
[IOC] Image ends with qgp2s6z.exe | Source: filename qgp2s6z.exe  
[IOC] Image ends with tt24n8xsl.exe | Source: filename tt24n8xsl.exe  

[BEHAVIOR] Detect DNS queries with failure status codes (e.g., NXDOMAIN, SERVFAIL) issued by processes that rarely perform DNS resolution (e.g., system services, background tasks) | Source: T1557  
[BEHAVIOR] Detect a high query rate (e.g., >100 DNS queries per minute) from a single process, indicating possible DNS‑based C2 or data exfiltration | Source: T1567  
[BEHAVIOR] Detect DNS queries occurring within 30 seconds of a service‑creation event (service execution) to surface potential post‑service‑execution C2 lookups | Source: T1569.002  
[BEHAVIOR] Detect DNS queries for newly observed domains issued by processes matching any of the malicious filenames (IoCs) to capture RAT‑initiated C2 lookups | Source: T1219  
[BEHAVIOR] Detect DNS queries for internal IP‑mapped hostnames (e.g., reverse‑lookup of 10.x.x.x, 192.168.x.x) following execution of enumeration tools, supporting remote system discovery activity | Source: T1018  

---

**Explanation of omitted items**

- **Attack patterns not directly tied to DNS activity** (T1021.002 — SMB/Windows Admin Shares, T1021.001 — RDP, T1190 — Exploit Public‑Facing Application, T1071 — Application‑Layer Protocol) primarily involve file sharing, remote desktop, or HTTP/HTTPS traffic. Sysmon Event ID 22 only records DNS queries; these techniques do not inherently generate observable DNS events, so they were excluded from the DNS‑focused recommendations.

- **Vulnerabilities (CVE‑2023‑3519, CVE‑2023‑48788, CVE‑2024‑57727, CVE‑2025‑5777)** describe remote code execution, SQL injection, path traversal, and memory over‑read respectively. None of these CVEs explicitly mandate or trigger DNS lookups as part of the exploit chain, and no domain or IP indicators are provided. Consequently, they do not yield actionable DNS‑specific monitoring rules and were omitted.