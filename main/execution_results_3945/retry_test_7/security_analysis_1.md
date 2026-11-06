[IOC] Image=wiseman.EXE | Hashes=SHA256=ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | Source: sha256  

[IOC] Image=wininet.dll | Hashes=SHA256=fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | Source: sha256  

[BEHAVIOR] Image=whoami.exe | CommandLine=whoami | Source: T1033  

[BEHAVIOR] Image=query.exe | CommandLine=query user | Source: T1033  

[BEHAVIOR] Image=systeminfo.exe | CommandLine=systeminfo | Source: T1082  

[BEHAVIOR] Image=ipconfig.exe | CommandLine=ipconfig /all | Source: T1016  

[BEHAVIOR] Image=route.exe | CommandLine=route print | Source: T1016  

[BEHAVIOR] Image=net.exe | CommandLine=net view | Source: T1018  

[BEHAVIOR] Image=rundll32.exe | CommandLine=* .cpl* | Source: T1218.011  

[BEHAVIOR] Image=rundll32.exe | CommandLine=*javascript:* | Source: T1218.011  

[BEHAVIOR] Image=sc.exe | CommandLine=* create * | Source: T1543.003  

[BEHAVIOR] Image=reg.exe | CommandLine=* query * | Source: T1012  

[BEHAVIOR] Image=certutil.exe | CommandLine=* -decode * | Source: T1140  

[BEHAVIOR] Image=copy.exe | CommandLine=* /b * | Source: T1140  

[BEHAVIOR] Image=powershell.exe | CommandLine=* -EncodedCommand * | Source: T1027  

[BEHAVIOR] Image=runas.exe | CommandLine=* /user:* | Source: T1134  

**Explanation of omitted items**  
- CVE‑2023‑27350 (PaperCut NG authentication bypass) is a vulnerability exploited via network requests; Sysmon Event ID 1 records only process‑creation metadata, so no specific process, command line, or file hash directly tied to the CVE is provided in the threat data. Therefore it cannot be targeted with a concrete Sysmon 1 rule.  
- ATT&CK techniques T1021 (Remote Services) and T1547.001 (Registry Run Keys / Startup Folder) are not represented by any explicit process‑creation artifacts in the supplied intelligence (no specific remote‑service binary or run‑key‑creation command is listed). Without concrete binaries or command‑line strings, a reliable Event 1 rule cannot be formulated, so they are omitted.  