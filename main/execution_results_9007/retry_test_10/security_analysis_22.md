[IOC] QueryName = incblog.su | Source: domain incblog.su  
[IOC] QueryName = incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion | Source: domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] QueryName = incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion | Source: domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[IOC] Image = *\x86_64-unknown-linux-esxi.elf | Source: filename x86_64-unknown-linux-esxi.elf  
[IOC] Image = *\h3odp7l2u.exe | Source: filename h3odp7l2u.exe  
[IOC] Image = *\hi9lezv.exe | Source: filename hi9lezv.exe  
[IOC] Image = *\072wiof7.exe | Source: filename 072wiof7.exe  
[IOC] Image = *\k0d649u.exe | Source: filename k0d649u.exe  
[IOC] Image = *\2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat | Source: filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image = *\2qfguc.exe | Source: filename 2qfguc.exe  
[IOC] Image = *\7hhel.exe | Source: filename 7hhel.exe  
[IOC] Image = *\3ctjhm3.exe | Source: filename 3ctjhm3.exe  
[IOC] Image = *\2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat | Source: filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image = *\bjiw49.exe | Source: filename bjiw49.exe  
[IOC] Image = *\7l73h.exe | Source: filename 7l73h.exe  
[IOC] Image = *\2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat | Source: filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image = *\0m6m882x2.exe | Source: filename 0m6m882x2.exe  
[IOC] Image = *\inc.exe | Source: filename inc.exe  
[IOC] Image = *\61pd6n3t.exe | Source: filename 61pd6n3t.exe  
[IOC] Image = *\mk1yd.exe | Source: filename mk1yd.exe  
[IOC] Image = *\a3mnw9.exe | Source: filename a3mnw9.exe  
[IOC] Image = *\win.bin | Source: filename win.bin  
[IOC] Image = *\vw06lg0y.exe | Source: filename vw06lg0y.exe  
[IOC] Image = *\qgp2s6z.exe | Source: filename qgp2s6z.exe  
[IOC] Image = *\tt24n8xsl.exe | Source: filename tt24n8xsl.exe  

[BEHAVIOR] DNS queries issued by processes that are not typical DNS resolvers (e.g., executable images not in a whitelist of browsers, OS services, or legitimate network utilities) – indicates possible command‑and‑control or data‑exfiltration over DNS. | Source: T1557  
[BEHAVIOR] DNS queries for .onion top‑level domains (including the two observed .onion indicators) – suggests use of Tor‑based C2 channels. | Source: T1071  
[BEHAVIOR] DNS queries returning NXDOMAIN, SERVFAIL, or other error status codes from processes that normally receive successful answers – may reflect DNS poisoning or domain‑fronting attempts. | Source: T1557  
[BEHAVIOR] High‑frequency DNS query bursts (multiple queries within <30 seconds) from a single process image – proxy for covert channel activity. | Source: T1071  
[BEHAVIOR] DNS queries for internal hostname patterns (e.g., *.corp, *.local) executed by enumeration utilities such as net.exe, ping.exe, tracert.exe – aligns with Remote System Discovery. | Source: T1018  

[DERIVED] DNS query (any name) that occurs within 5 minutes before a SMB admin‑share access event (e.g., process accesses C$ or ADMIN$) – potential indicator of lateral movement using SMB. | Source: T1021.002  
[DERIVED] DNS query (any name) that occurs within 5 minutes before a successful RDP (remote desktop) logon – can flag pre‑connection name resolution for lateral movement. | Source: T1021.001  
[DERIVED] DNS query that follows a change to system DNS configuration (registry or network settings) within the correlation window – may denote a DNS‑poisoning or MiTM setup. | Source: T1557  

--- Omitted Items Explanation ---  
- T1190 (Exploit Public‑Facing Application): The technique involves exploiting a vulnerable service; Sysmon Event 22 records DNS queries only and does not provide visibility into HTTP request patterns, payloads, or service errors required to detect this exploit.  
- T1567 (Exfiltration Over Web Service): This technique uses legitimate web services for data exfiltration and does not inherently involve DNS resolution beyond normal name lookup, which is not distinctive for detection.  
- T1569.002 (Service Execution): Relates to creating or invoking Windows services; DNS query events do not convey service creation or execution details, so no relevant monitoring can be derived from Event 22.  

All recommendations above are directly observable via Sysmon Event 22 fields (QueryName, QueryStatus, QueryResults, Image) and are anchored to the supplied IoCs, ATT&CK techniques, or logical derivations from the provided context.