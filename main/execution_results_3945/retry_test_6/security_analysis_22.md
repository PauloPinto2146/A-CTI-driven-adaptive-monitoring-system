[IOC] Image contains “wiseman.exe” | Source: IOC filename wiseman.EXE  
[BEHAVIOR] Image contains “rundll32.exe” | Source: ATT&CK T1218.011  
[BEHAVIOR] QueryName length > 30 characters (indicative of encoded/subdomain payload) | Source: ATT&CK T1071.004  
[BEHAVIOR] Image matches non‑browser, non‑system executables (e.g., PowerShell.exe, python.exe) making DNS queries | Source: ATT&CK T1071.004  
[DERIVED] DNS query (any Image) occurring within 60 seconds of a remote service logon event (e.g., mstsc.exe, wmiprvse.exe) | Source: ATT&CK T1021  

**Why omitted indicators were not included**

- **wininet.dll** – This is a DLL, not a process. EventID 22 records the process image that initiates the DNS query; it does not capture loaded modules, so wininet.dll cannot be directly observed here.  
- **CVE‑2023‑27350** – The vulnerability concerns unauthenticated remote code execution in PaperCut NG and does not involve DNS resolution activity; therefore it cannot be detected via Sysmon DNS query events.  
- **T1021 (Remote Services), T1018 (Remote System Discovery), T1102.001 (Dead Drop Resolver)** – These techniques may involve DNS lookups in broader attack chains, but the provided context does not specify concrete DNS‑related behaviors (e.g., particular domains, query patterns) that can be directly mapped to EventID 22. Consequently, only a derived correlation (as listed above) is possible, and no direct, concrete monitoring rule can be justified.