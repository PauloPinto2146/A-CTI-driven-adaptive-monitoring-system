[IOC] ImageLoaded=wininet.dll | Hashes=SHA256:fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | Source: IoC (wininet.dll)  
[IOC] ImageLoaded=wiseman.EXE | Hashes=SHA256:ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IoC (wiseman.EXE)  
[BEHAVIOR] Image=rundll32.exe | ImageLoaded=any DLL not present in the environment‑specific AllowedDLLs baseline | Source: T1218.011  
[BEHAVIOR] Image=cmd.exe | ImageLoaded=any DLL loaded from %TEMP% or C:\Users\Public (or other atypical script locations) | Source: T1059.003  
[DERIVED] Image=svchost.exe (or any privileged service process) | ImageLoaded=module that is unsigned or has a signature status of “Unknown/Invalid” | Source: CVE-2023-27350