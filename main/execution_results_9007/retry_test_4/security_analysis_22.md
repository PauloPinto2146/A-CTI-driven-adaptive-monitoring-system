[IOC] QueryName == incblog.su | Source: IOC domain incblog.su  
[IOC] QueryName == incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion | Source: IOC domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] QueryName == incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion | Source: IOC domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[IOC] Image == x86_64-unknown-linux-esxi.elf | Source: IOC filename x86_64-unknown-linux-esxi.elf  
[IOC] Image == h3odp7l2u.exe | Source: IOC filename h3odp7l2u.exe  
[IOC] Image == hi9lezv.exe | Source: IOC filename hi9lezv.exe  
[IOC] Image == 072wiof7.exe | Source: IOC filename 072wiof7.exe  
[IOC] Image == k0d649u.exe | Source: IOC filename k0d649u.exe  
[IOC] Image == 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat | Source: IOC filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image == 2qfguc.exe | Source: IOC filename 2qfguc.exe  
[IOC] Image == 7hhel.exe | Source: IOC filename 7hhel.exe  
[IOC] Image == 3ctjhm3.exe | Source: IOC filename 3ctjhm3.exe  
[IOC] Image == 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat | Source: IOC filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image == bjiw49.exe | Source: IOC filename bjiw49.exe  
[IOC] Image == 7l73h.exe | Source: IOC filename 7l73h.exe  
[IOC] Image == 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat | Source: IOC filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image == 0m6m882x2.exe | Source: IOC filename 0m6m882x2.exe  
[IOC] Image == inc.exe | Source: IOC filename inc.exe  
[IOC] Image == 61pd6n3t.exe | Source: IOC filename 61pd6n3t.exe  
[IOC] Image == mk1yd.exe | Source: IOC filename mk1yd.exe  
[IOC] Image == a3mnw9.exe | Source: IOC filename a3mnw9.exe  
[IOC] Image == win.bin | Source: IOC filename win.bin  
[IOC] Image == vw06lg0y.exe | Source: IOC filename vw06lg0y.exe  
[IOC] Image == qgp2s6z.exe | Source: IOC filename qgp2s6z.exe  
[IOC] Image == tt24n8xsl.exe | Source: IOC filename tt24n8xsl.exe  

[BEHAVIOR] QueryStatus != 0 (failed, NXDOMAIN, SERVFAIL, REFUSED) indicating possible DNS poisoning or interception | Source: ATT&CK T1557 (Adversary-in-the-Middle)  
[BEHAVIOR] Image not in a baseline allow‑list of known system binaries (e.g., svchost.exe, explorer.exe, rundll32.exe) making DNS queries – suspicious DNS‑based C2 activity | Source: ATT&CK T1071 (Application Layer Protocol)  
[BEHAVIOR] Multiple distinct QueryName values (>=5) observed from the same Image within a 60‑second window – indicative of DNS tunneling or exfiltration over DNS | Source: ATT&CK T1071 (Application Layer Protocol)  

[DERIVED] Correlate DNS queries (EventID 22) from images matching known remote‑access tool binaries (e.g., any of the listed filenames) with subsequent creation of network sockets or remote sessions – possible use of RATs for C2 over DNS | Source: ATT&CK T1219 (Remote Access Tools)  

[DERIVED] Detect DNS queries for newly‑seen external domains (not previously resolved on the host) originating from processes that have recently spawned from exploitation of a public‑facing service (e.g., after a request pattern matching DET0080) – potential post‑exploit C2 channel | Source: ATT&CK T1190 (Exploit Public‑Facing Application)