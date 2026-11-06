[BEHAVIOR] Detect driver loads where Signed = false (unsigned driver) | Source: T1543.003  
[BEHAVIOR] Detect driver loads where ImageLoaded path resides outside the Windows system driver directory (e.g., not under %SystemRoot%\System32\drivers) | Source: T1543.003  
[BEHAVIOR] Detect driver loads where SignatureStatus is not “Valid” (e.g., “Invalid”, “Unknown”, “Unsigned”) | Source: CVE-2023-27350  

**Omissions explanation**  
- The IoCs {sha256: ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205, filename: wiseman.EXE} and {sha256: fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c, filename: wininet.dll} refer to an executable and a DLL, respectively. Event ID 6 records driver‑load events only, so these indicators cannot be observed via this event type.  

- Attack pattern T1543.003 (Windows Service) describes creating/modifying services that may install malicious drivers, but no concrete service names, driver file names, or hashes are provided. Consequently, only generic behavior (e.g., unsigned drivers, non‑system locations, invalid signatures) can be recommended for monitoring with Event ID 6.