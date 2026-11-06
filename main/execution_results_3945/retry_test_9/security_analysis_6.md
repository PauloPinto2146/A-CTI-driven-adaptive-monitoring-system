[BEHAVIOR] ImageLoaded path matches “C:\Users\*” or “C:\Temp\*” (driver loaded from a user‑profile or temporary directory) | Source: T1543.003  
[BEHAVIOR] Signed = false OR SignatureStatus = “Unsigned” or “Invalid” (unsigned or improperly signed driver loaded) | Source: T1543.003  
[BEHAVIOR] ImageLoaded ends with “.sys” and resides outside of the default driver directory (e.g., not under %SystemRoot%\System32\drivers) | Source: T1543.003  

**Explanation for omitted indicators**  
- The provided IOC hashes (wiseman.EXE and wininet.dll) refer to an executable and a DLL, not to driver files (*.sys). Sysmon Event ID 6 records only driver‑load events, so these IOC values cannot be observed with this event type.  
- CVE‑2023‑27350 is a network‑based authentication bypass in PaperCut NG that results in arbitrary code execution as SYSTEM, but it does not involve loading a driver. Consequently, it is not relevant to monitoring Event ID 6.