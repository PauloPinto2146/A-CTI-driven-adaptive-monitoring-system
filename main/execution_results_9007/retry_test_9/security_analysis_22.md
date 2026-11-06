[IOC] QueryName == incblog.su | Source: domain incblog.su  
[IOC] QueryName == incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion | Source: domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] QueryName == incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion | Source: domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[IOC] Image == *\h3odp7l2u.exe* issuing DNS query | Source: filename h3odp7l2u.exe  
[IOC] Image == *\hi9lezv.exe* issuing DNS query | Source: filename hi9lezv.exe  
[IOC] Image == *\072wiof7.exe* issuing DNS query | Source: filename 072wiof7.exe  
[IOC] Image == *\k0d649u.exe* issuing DNS query | Source: filename k0d649u.exe  
[IOC] Image == *\2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat* issuing DNS query | Source: filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image == *\2qfguc.exe* issuing DNS query | Source: filename 2qfguc.exe  
[IOC] Image == *\7hhel.exe* issuing DNS query | Source: filename 7hhel.exe  
[IOC] Image == *\3ctjhm3.exe* issuing DNS query | Source: filename 3ctjhm3.exe  
[IOC] Image == *\2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat* issuing DNS query | Source: filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image == *\bjiw49.exe* issuing DNS query | Source: filename bjiw49.exe  
[IOC] Image == *\7l73h.exe* issuing DNS query | Source: filename 7l73h.exe  
[IOC] Image == *\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat* issuing DNS query | Source: filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image == *\0m6m882x2.exe* issuing DNS query | Source: filename 0m6m882x2.exe  
[IOC] Image == *\inc.exe* issuing DNS query | Source: filename inc.exe  
[IOC] Image == *\61pd6n3t.exe* issuing DNS query | Source: filename 61pd6n3t.exe  
[IOC] Image == *\mk1yd.exe* issuing DNS query | Source: filename mk1yd.exe  
[IOC] Image == *\a3mnw9.exe* issuing DNS query | Source: filename a3mnw9.exe  
[IOC] Image == *\win.bin* issuing DNS query | Source: filename win.bin  
[IOC] Image == *\vw06lg0y.exe* issuing DNS query | Source: filename vw06lg0y.exe  
[IOC] Image == *\qgp2s6z.exe* issuing DNS query | Source: filename qgp2s6z.exe  
[IOC] Image == *\tt24n8xsl.exe* issuing DNS query | Source: filename tt24n8xsl.exe  
[IOC] Image == *\x86_64-unknown-linux-esxi.elf* issuing DNS query | Source: filename x86_64-unknown-linux-esxi.elf  

[BEHAVIOR] QueryStatus == NXDOMAIN or REFUSED (failed resolution) indicating possible DNS poisoning or tunneling activity | Source: T1557 (Adversary-in-the-Middle)  
[BEHAVIOR] QueryStatus == NOERROR with unusually large Answer section (e.g., >5 resource records) suggesting data exfiltration via DNS | Source: T1071 (Application Layer Protocol)  

[DERIVED] QueryName length > 50 characters (possible DNS tunneling payload) | Source: T1071  
[DERIVED] More than 100 DNS queries from the same Image within a 1‑minute window (high query rate) | Source: T1071  
[DERIVED] DNS queries from processes running from known vulnerable product install paths (e.g., FortiClientEMS) shortly after a CVE‑2023‑48788 exploit attempt | Source: CVE-2023-48788  
[DERIVED] DNS queries observed from processes that have recently created or modified network‑related registry keys (e.g., DNS/ARP settings) – a behavior linked to T1557 | Source: T1557  

---

**Explanation of omitted IoCs and attack patterns**

- **Filenames not listed above** (e.g., any of the provided executables that have not been observed issuing DNS queries) were omitted because Sysmon Event ID 22 records only DNS activity. Without evidence that a particular file initiates a DNS request, monitoring its presence would not be observable through this event type.

- **Attack patterns T1190, T1567, T1219, T1021.002, T1018, T1021.001, T1569.002** focus on exploiting public‑facing services, web‑service exfiltration, remote access tools, SMB admin‑share lateral movement, system discovery, RDP logins, and service execution. None of these techniques inherently generate DNS queries; therefore they do not produce data capturable by Event ID 22 and are excluded from the recommendations.

- **Vulnerabilities CVE‑2023‑3519, CVE‑2024‑57727, CVE‑2025‑5777** describe remote code execution, path traversal, or memory over‑read exploits that do not specifically trigger DNS resolution. While a compromised host might later issue DNS queries as part of post‑exploitation traffic, the vulnerabilities themselves do not provide concrete DNS‑related IoCs, so only derived, behavior‑based recommendations are provided for them.