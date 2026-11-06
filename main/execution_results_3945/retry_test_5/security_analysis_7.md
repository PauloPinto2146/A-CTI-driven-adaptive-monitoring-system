[IOC] Detect loading of an image with SHA256 = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (wiseman.EXE) | Source: IoC (wiseman.EXE hash)  
[IOC] Detect loading of an image with SHA256 = fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c (wininet.dll) | Source: IoC (wininet.dll hash)  
[BEHAVIOR] Detect rundll32.exe (Image) loading any ImageLoaded ending in “.cpl” (Control Panel item files) | Source: T1218.011  
[BEHAVIOR] Detect rundll32.exe (Image) loading any ImageLoaded with a .dll extension that is not present in an environment‑specific AllowedDLLs baseline | Source: T1218.011  
[BEHAVIOR] Detect rundll32.exe (Image) loading any unsigned or signature‑invalid ImageLoaded (Signed = false or SignatureStatus ≠ Valid) | Source: T1218.011  
[DERIVED] Detect any process loading an ImageLoaded located under the PaperCut NG installation path (e.g., C:\Program Files\PaperCut\*) | Source: CVE-2023-27350  
[BEHAVIOR] Detect cmd.exe (Image) loading any ImageLoaded from temporary or public directories (e.g., %TEMP%, C:\Users\Public) as part of batch script execution | Source: T1059.003