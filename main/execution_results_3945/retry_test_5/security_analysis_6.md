[BEHAVIOR] ImageLoaded path located in uncommon directories (e.g., C:\Users\*, C:\Temp\*, %AppData%\*) | Source: T1543.003  
[BEHAVIOR] Signed = false (driver is unsigned) | Source: T1543.003  
[DERIVED] SignatureStatus is “Unknown”, “Invalid” or otherwise indicates a problematic signature | Source: CVE-2023-27350  

**Explanation for omitted items**  
- The IoCs `wiseman.EXE` (sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205) and `wininet.dll` (sha256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c) are an executable and a DLL, not driver files (*.sys). Sysmon EventID 6 records driver‑load events only, so these hashes cannot be observed with this event type.  
- The attack pattern T1543.003 is incorporated in the behavioral recommendations above (monitoring unsigned drivers, uncommon load paths, and signature problems). No concrete IoC from the pattern was omitted.