[IOC] Image path contains “wiseman.exe” | Source: IOC filename: wiseman.EXE  
[BEHAVIOR] Image ends with “rundll32.exe” (process invoking DNS queries) | Source: T1218.011  
[BEHAVIOR] QueryName length ≥ 50 characters (indicative of encoded payloads) | Source: T1071.004  
[BEHAVIOR] Image matches remote‑service client executables (e.g., mstsc.exe, ssh.exe, plink.exe) making DNS queries | Source: T1021  
[BEHAVIOR] Image matches network‑enumeration utilities (net.exe, ping.exe, tracert.exe) that issue DNS queries | Source: T1018  

**Omitted items and rationale**  
- **wininet.dll** – Sysmon Event ID 22 records the process image that performs the DNS lookup; it does not capture DLL names or module loads, so this IOC cannot be observed directly via this event.  
- **CVE‑2023‑27350** – The vulnerability pertains to authentication bypass in PaperCut NG and does not involve DNS activity; therefore it is outside the observable scope of Event ID 22.  
- **T1102.001 (Dead Drop Resolver)** – No specific dead‑drop domains or URLs are provided in the threat data; without concrete domain indicators, Event ID 22 cannot be targeted to this technique.  
- **T1021 (Remote Services) and T1018 (Remote System Discovery)** – While these techniques can indirectly use DNS, the provided context does not specify particular processes, domains, or query patterns unique to them, so only generic behavioral cues (e.g., remote‑service client binaries) are included rather than technique‑specific IOC monitoring.