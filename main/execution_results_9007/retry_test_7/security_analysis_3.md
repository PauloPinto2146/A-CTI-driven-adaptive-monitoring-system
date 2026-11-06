[IOC] Image = "x86_64-unknown-linux-esxi.elf" | Source: IOC filename x86_64-unknown-linux-esxi.elf  
[IOC] Image = "h3odp7l2u.exe" | Source: IOC filename h3odp7l2u.exe  
[IOC] Image = "hi9lezv.exe" | Source: IOC filename hi9lezv.exe  
[IOC] Image = "072wiof7.exe" | Source: IOC filename 072wiof7.exe  
[IOC] Image = "k0d649u.exe" | Source: IOC filename k0d649u.exe  
[IOC] Image = "2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat" | Source: IOC filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image = "2qfguc.exe" | Source: IOC filename 2qfguc.exe  
[IOC] Image = "7hhel.exe" | Source: IOC filename 7hhel.exe  
[IOC] Image = "3ctjhm3.exe" | Source: IOC filename 3ctjhm3.exe  
[IOC] Image = "2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat" | Source: IOC filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image = "bjiw49.exe" | Source: IOC filename bjiw49.exe  
[IOC] Image = "7l73h.exe" | Source: IOC filename 7l73h.exe  
[IOC] Image = "2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat" | Source: IOC filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Image = "0m6m882x2.exe" | Source: IOC filename 0m6m882x2.exe  
[IOC] Image = "inc.exe" | Source: IOC filename inc.exe  
[IOC] Image = "61pd6n3t.exe" | Source: IOC filename 61pd6n3t.exe  
[IOC] Image = "mk1yd.exe" | Source: IOC filename mk1yd.exe  
[IOC] Image = "a3mnw9.exe" | Source: IOC filename a3mnw9.exe  
[IOC] Image = "win.bin" | Source: IOC filename win.bin  
[IOC] Image = "vw06lg0y.exe" | Source: IOC filename vw06lg0y.exe  
[IOC] Image = "qgp2s6z.exe" | Source: IOC filename qgp2s6z.exe  
[IOC] Image = "tt24n8xsl.exe" | Source: IOC filename tt24n8xsl.exe  

[IOC] DestinationHostname = "incblog.su" | Source: IOC domain incblog.su  
[IOC] DestinationHostname = "incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion" | Source: IOC domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] DestinationHostname = "incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion" | Source: IOC domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[BEHAVIOR] Protocol = TCP, DestinationPort = 3389 (Remote Desktop) | Source: T1021.001  
[BEHAVIOR] Protocol = TCP, DestinationPort = 445 (SMB/Windows Admin Shares) | Source: T1021.002  
[BEHAVIOR] Protocol = TCP, DestinationPort in {80,443,53,445} and Image NOT IN ["svchost.exe","explorer.exe","lsass.exe","services.exe","wininit.exe"] (suspicious use of common app‑layer protocols) | Source: T1071  
[BEHAVIOR] Image = "services.exe" establishing any network connection (service‑execution induced traffic) | Source: T1569.002  
[BEHAVIOR] Protocol = TCP, DestinationPort = 53 (DNS) with rapid succession of distinct DestinationIp values (possible DNS/ARP poisoning activity) | Source: T1557  
[BEHAVIOR] Protocol = TCP, DestinationPort = 80 or 443 with high count of distinct DestinationHostname values within a short TimeWindow (potential exfiltration over web services) | Source: T1567  
[BEHAVIOR] Protocol = TCP, DestinationPort = any, and multiple distinct DestinationIp observed from the same Image within <30 seconds (remote system discovery / enumeration) | Source: T1018  

---  

**Why other IoCs/attack patterns were not included**

* SHA‑256 hash values were omitted because EventID 3 does not capture file hashes; it only logs the process image name. Without a corresponding filename in the event, the hash cannot be correlated.  
* The vulnerability identifiers (CVE‑2023‑3519, CVE‑2023‑48788, CVE‑2024‑57727, CVE‑2025‑5777) describe server‑side flaws in network‑exposed services. Sysmon’s network‑connection event on the endpoint cannot directly reveal exploitation of those CVEs (e.g., no specific request payloads, error codes, or vulnerable service names are logged), so no concrete monitoring rule can be derived for them from this event type.  
* Attack patterns that rely on behaviors not exposed by a connection event (e.g., registry modifications, DLL loading, process injection, or credential dumping) were excluded because they cannot be observed with EventID 3 alone. Only the behaviors and indicators that map to fields present in the network‑connection log (Image, Protocol, ports, IPs, hostnames) are recommended.