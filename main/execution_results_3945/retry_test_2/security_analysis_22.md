[IOC] DNS queries where Image = "wiseman.EXE" | Source: IOC – filename wiseman.EXE  
[BEHAVIOR] DNS queries where Image = "rundll32.exe" (monitor for potential Rundll32 abuse) | Source: T1218.011  
[BEHAVIOR] DNS queries from non‑browser, non‑system processes (e.g., PowerShell.exe, python.exe, rundll32.exe) | Source: T1071.004  
[DERIVED] DNS queries that occur within a short time window after a remote service login (RDP/WMI) by any user account | Source: T1021  
[DERIVED] DNS queries whose QueryName resolves to external domains/IP ranges outside the organization’s trusted DNS zones (possible dead‑drop resolver activity) | Source: T1102.001  

**Explanation of omitted items**

- **wininet.dll** – Sysmon Event ID 22 records the process executable (Image) that makes a DNS query, not the DLLs loaded by that process. Since the event cannot directly capture the presence of wininet.dll, it cannot be monitored with this event type.  
- **T1018 (Remote System Discovery)** – This technique involves enumeration utilities (e.g., net view, ping) and does not intrinsically generate DNS query events. Therefore, it cannot be observed through Event 22 and is omitted.  
- **CVE‑2023‑27350** – The vulnerability concerns authentication bypass in PaperCut NG and does not involve DNS query behavior; consequently, it provides no observable signal for Event 22.