[BEHAVIOR] ImageLoaded path matches uncommon locations (e.g., `C:\Users\*\.sys` or `C:\Temp\*\.sys`) | Source: T1543.003  
[BEHAVIOR] Signed = false (unsigned driver) | Source: T1543.003  
[BEHAVIOR] SignatureStatus != "Verified" (e.g., “Invalid”, “Unknown”, “No signature”) | Source: T1543.003  
[BEHAVIOR] ImageLoaded extension is `.sys` and the load occurs in the context of a service creation or `sc.exe`/`CreateServiceW` usage | Source: T1543.003  

*Omitted indicators of compromise:*  
- **wiseman.EXE** (SHA‑256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205) – excluded because Event ID 6 reports only driver loads; an executable file load would appear in a different Sysmon event (e.g., ImageLoad Event ID 7).  
- **wininet.dll** (SHA‑256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c) – similarly excluded since a DLL load is not captured by the driver‑load event; Sysmon records DLL loads under a separate event ID.