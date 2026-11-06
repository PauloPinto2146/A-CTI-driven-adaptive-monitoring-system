[IOC] ImageLoaded = wininet.dll, Hashes = fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | Source: IoC sha256 wininet.dll  
[IOC] ImageLoaded = wiseman.EXE, Hashes = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IoC sha256 wiseman.EXE  
[BEHAVIOR] Image = rundll32.exe AND ImageLoaded ends with ".cpl" (Control Panel item) | Source: T1218.011  
[BEHAVIOR] Image = rundll32.exe AND ImageLoaded ends with ".dll" AND ImageLoaded NOT IN AllowedDLLs (baseline list of legitimate DLLs) | Source: T1218.011  
[BEHAVIOR] Image = rundll32.exe AND ImageLoaded path starts with "\\" (UNC network location) | Source: T1218.011  
[BEHAVIOR] Image = cmd.exe AND ImageLoaded ends with ".dll" AND ImageLoaded NOT IN AllowedDLLs (baseline list of legitimate DLLs for cmd) | Source: T1059.003  

All IoCs and attack patterns from the provided context have been considered; no recommendation related to CVE‑2023‑27350 is included because the vulnerability pertains to an authentication bypass in PaperCut NG and does not manifest as a module‑load event that can be captured by Sysmon EventID 7.