[IOC] ImageLoaded: *wiseman.EXE* | Hashes: SHA256=ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: IoC – wiseman.EXE hash  

[IOC] ImageLoaded: *wininet.dll* | Hashes: SHA256=fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | Source: IoC – wininet.dll hash  

[BEHAVIOR] Image: *rundll32.exe* | ImageLoaded: *.cpl* | SignatureStatus: any | Source: ATT&CK T1218.011  

[BEHAVIOR] Image: *rundll32.exe* | ImageLoaded: *.dll* | SignatureStatus: any | AdditionalCondition: DLL not listed in environment‑specific AllowedDLLs | Source: ATT&CK T1218.011  

[BEHAVIOR] Image: *rundll32.exe* | ImageLoaded: *.js* | SignatureStatus: any | Source: ATT&CK T1218.011  

[BEHAVIOR] Image: *rundll32.exe* | ImageLoaded: *.sct* | SignatureStatus: any | Source: ATT&CK T1218.011  

[DERIVED] Image: *any privileged process (e.g., services running as SYSTEM)* | ImageLoaded: *any unsigned or improperly signed module* | SignatureStatus: invalid or missing | Source: CVE‑2023‑27350 (arbitrary code execution in System context)  