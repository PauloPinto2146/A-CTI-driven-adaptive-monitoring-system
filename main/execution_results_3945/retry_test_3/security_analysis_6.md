[BEHAVIOR] ImageLoaded matches regex `.*\\(Users|Temp|AppData)\\.*\.sys` | Source: T1543.003  
[BEHAVIOR] Signed = false OR SignatureStatus != "Valid" | Source: T1543.003  
[DERIVED] ImageLoaded ends with `.sys` **and** the load occurs within a short temporal window (e.g., 60 s) after a Windows service creation event (Sysmon EventID 1 indicating a new service) | Source: T1543.003  

**Omission explanation:** The indicators of compromise supplied (wiseman.EXE sha256 ebba8f4342b… and wininet.dll sha256 fda9864b1a…) are regular executables/DLLs, not driver files. Sysmon Event ID 6 records only driver‑load events, so these IoCs cannot be observed through this event type and were therefore excluded from the analysis.