[IOC] Image matches any of the reported malicious executable names (h3odp7l2u.exe, hi9lezv.exe, 072wiof7.exe, k0d649u.exe, 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat, 2qfguc.exe, 7hhel.exe, 3ctjhm3.exe, 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat, bjiw49.exe, 7l73h.exe, 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat, 0m6m882x2.exe, inc.exe, 61pd6n3t.exe, mk1yd.exe, a3mnw9.exe, win.bin, vw06lg0y.exe, qgp2s6z.exe, tt24n8xsl.exe) | Source: filename (IoC)

[IOC] QueryName = incblog.su | Source: domain incblog.su (IoC)

[BEHAVIOR] QueryStatus = NXDOMAIN or other DNS error codes (e.g., SERVFAIL, REFUSED) that may indicate DNS poisoning or failed resolution attempts | Source: T1557 – Adversary‑in‑the‑Middle (DNS manipulation)

[BEHAVIOR] QueryName ≠ internal corporate zones (i.e., queries for external, non‑whitelisted domains) combined with Image ≠ known legitimate system utilities (e.g., svchost.exe, nslookup.exe) – indicative of covert C2 over DNS | Source: T1071 – Application Layer Protocol (DNS‑based C2) 

[BEHAVIOR] Surge in DNS query volume from a single Image (e.g., > X queries within Y seconds) suggesting exfiltration or tunneling activity | Source: T1071 (c2 over DNS) / T1567 (Exfiltration Over Web Service) – derived behavioral indication

[BEHAVIOR] DNS queries occurring within T minutes after a service execution event (e.g., services.exe spawning a non‑allowlisted binary) – possible post‑service‑execution C2 or data exfiltration | Source: T1569.002 – Service Execution (derived)