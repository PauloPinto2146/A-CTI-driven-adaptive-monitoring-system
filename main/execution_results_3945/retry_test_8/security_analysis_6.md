[BEHAVIOR] ImageLoaded path located in user‑writable directories (e.g., C:\Users\*, C:\Temp\*, %TEMP%*) | Source: T1543.003  
[BEHAVIOR] Signed = false or SignatureStatus ≠ “Valid” (detect unsigned or improperly signed drivers) | Source: T1543.003  
[BEHAVIOR] ImageLoaded filename does not match known Windows system driver names (i.e., an uncommon or suspicious driver name) | Source: T1543.003  
[BEHAVIOR] ParentProcessName is sc.exe or svchost.exe when a driver is loaded (indicates driver load via service creation APIs such as CreateServiceW) | Source: T1543.003  

**Omitted IoCs and CVE explanation:**  
- The provided hashes ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (wiseman.EXE) and fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c (wininet.dll) refer to an executable and a DLL, not to driver files (.sys). Sysmon Event ID 6 records only driver‑load events, so these IoCs cannot be observed via this event type.  
- CVE‑2023‑27350 describes a network‑based authentication bypass in PaperCut NG that leads to arbitrary code execution as SYSTEM. It does not involve loading a driver, nor does it specify any driver‑related artifacts. Consequently, there is no driver‑load observable tied to this vulnerability for Event ID 6.