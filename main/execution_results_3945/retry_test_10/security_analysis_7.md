[IOC] ImageLoaded hash equals ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (wiseman.EXE) | Source: IoC – wiseman.EXE SHA256  
[IOC] ImageLoaded hash equals fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c (wininet.dll) | Source: IoC – wininet.dll SHA256  
[BEHAVIOR] Image (process) equals rundll32.exe and ImageLoaded extension equals .cpl (| .cpl files) | Source: T1218.011  
[BEHAVIOR] Image (process) equals rundll32.exe and ImageLoaded is not in the environment’s baseline list of allowed DLLs (AllowedDLLs) | Source: T1218.011  
[BEHAVIOR] Image (process) equals cmd.exe and ImageLoaded path resides in %TEMP% or C:\Users\Public or an external drive location | Source: T1059.003  
[DERIVED] ImageLoaded is unsigned (Signed = false) when loaded by any process running as SYSTEM | Source: CVE-2023-27350  
[DERIVED] ImageLoaded has Product or Company fields that do not match known legitimate Microsoft products when loaded by rundll32.exe or cmd.exe | Source: T1218.011 / T1059.003