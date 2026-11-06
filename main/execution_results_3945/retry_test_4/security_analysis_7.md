[IOC] ImageLoaded hash fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c (filename wininet.dll) | Source: IOC (wininet.dll SHA‑256)  
[IOC] ImageLoaded hash ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (filename wiseman.EXE) | Source: IOC (wiseman.EXE SHA‑256)  
[BEHAVIOR] Image == rundll32.exe AND ImageLoaded ends with “.cpl” (Control‑Panel item) | Source: T1218.011  
[BEHAVIOR] Image == rundll32.exe AND ImageLoaded ends with “.dll” that is not in the environment’s AllowedDLLs list (atypical DLL) | Source: T1218.011  
[BEHAVIOR] Image == rundll32.exe AND ImageLoaded uses script protocols (e.g., “javascript:”, “mshtml”) or loads “.sct”, “.hta”, or “.js” files | Source: T1218.011  
[BEHAVIOR] Image == cmd.exe AND ImageLoaded path contains %TEMP% or C:\Users\Public or external drive locations | Source: T1059.003  
[BEHAVIOR] Image == cmd.exe AND ImageLoaded is unsigned or has signature status “invalid” or “missing” | Source: T1059.003  