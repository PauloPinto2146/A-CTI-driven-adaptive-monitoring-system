[BEHAVIOR] Detect driver loads where **ImageLoaded** resides outside standard system driver locations (e.g., not under `%SystemRoot%\System32\drivers`) and is located in user‑writable paths such as `C:\Users\*`, `C:\Temp\*`, or other non‑system directories. | Source: T1543.003  

[BEHAVIOR] Detect driver loads where **Signed** is false **or** **SignatureStatus** is not `Valid` (e.g., `Unsigned`, `Invalid`, `Unknown`). | Source: T1543.003  

[DERIVED] Detect driver loads whose **ImageLoaded** path matches the **ImagePath** configured for a Windows service that was created or modified within the *StartupTypeChangeWindow* (temporal window defined for correlating service registry `Start` changes with driver installation). | Source: T1543.003  

---  
**Omitted IoCs**  

- `wiseman.EXE` (SHA‑256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205): this is an executable, not a driver; Sysmon Event ID 6 records only driver loads, so the hash cannot be observed here.  

- `wininet.dll` (SHA‑256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c): this is a DLL, not a driver; therefore it is not applicable to driver‑load monitoring.  

**Omitted Vulnerability**  

- CVE‑2023‑27350: the described vulnerability enables remote code execution via authentication bypass in PaperCut NG, but it does not intrinsically involve loading a kernel driver. Consequently, no direct driver‑load indicators are derived from the CVE description; the DERIVED recommendation above anticipates a possible post‑exploitation scenario where an attacker might load a malicious driver for persistence or escalation.