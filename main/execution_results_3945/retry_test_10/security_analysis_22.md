[BEHAVIOR] Monitor DNS queries where Image equals “rundll32.exe” (any path) | Source: T1218.011  
[IOC] Monitor DNS queries where Image equals “wiseman.EXE” (any path) | Source: wiseman.EXE  
[BEHAVIOR] Detect DNS queries with QueryName length greater than typical hostnames (e.g., > 50 characters) to flag potential base64/base32 encoded payloads | Source: T1071.004  
[BEHAVIOR] Flag DNS queries initiated by non‑browser, non‑system processes (e.g., PowerShell, python.exe, rundll32.exe) | Source: T1071.004  

**Explanation of omitted items**  
- The IOC “wininet.dll” is a library, not an executable process; EventID 22 only records the Image (process) making the DNS query, so it cannot be directly monitored.  
- Attack patterns T1021 (Remote Services), T1018 (Remote System Discovery), and T1102.001 (Dead Drop Resolver) describe activities that do not involve DNS query generation by a process, thus they are not applicable to Sysmon Event 22.  
- CVE‑2023‑27350 describes an authentication bypass in PaperCut NG and does not involve DNS query behavior observable via Event 22.