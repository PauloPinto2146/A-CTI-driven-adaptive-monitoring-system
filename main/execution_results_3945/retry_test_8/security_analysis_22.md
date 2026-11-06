[IOC] Image == "wiseman.EXE" | Source: IOC filename  
[BEHAVIOR] Image == "rundll32.exe" | Source: T1218.011  
[BEHAVIOR] ProcessImage in { "powershell.exe", "python.exe", "rundll32.exe" } making DNS queries (non‑browser, non‑system) | Source: T1071.004  
[BEHAVIOR] QueryName length > 50 characters (indicative of encoded payloads) | Source: T1071.004  
[DERIVED] Image in { "net.exe", "ping.exe", "tracert.exe" } issuing DNS queries in rapid succession (burst within short TimeWindow) | Source: T1018  

**Why “wininet.dll” was not used:** Event ID 22 records only the querying process (Image), the DNS name, status, and results. It does not capture which DLLs a process has loaded, so there is no direct observable field for “wininet.dll” in this event type. Consequently, it cannot be monitored via Sysmon 22.  

**Why T1021 (Remote Services) was not included:** The provided ATT&CK description for T1021 does not specify DNS query usage as part of the technique, and Event 22 cannot infer remote‑service login activity beyond the DNS query itself. Therefore, no recommendation specific to T1021 can be justified using this event type.  

**Why CVE‑2023‑27350 was not included:** The vulnerability pertains to authentication bypass in PaperCut NG and does not involve DNS query behavior. Sysmon 22 cannot capture the exploitation steps described, so no relevant recommendation can be derived.  