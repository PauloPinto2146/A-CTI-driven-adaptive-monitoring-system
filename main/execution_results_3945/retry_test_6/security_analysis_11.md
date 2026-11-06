[IOC] Image: any, TargetFilename: wiseman.EXE, CreationUtcTime: any | Source: IOC filename wiseman.EXE  
[IOC] Image: any, TargetFilename: wininet.dll, CreationUtcTime: any | Source: IOC filename wininet.dll  
[BEHAVIOR] Image: any, TargetFilename matches *.dll in %TEMP% or %USERPROFILE%\Downloads, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: any, TargetFilename matches *.cpl in %TEMP% or %USERPROFILE%\Downloads, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: any, TargetFilename matches *.sct in %TEMP% or %USERPROFILE%\Downloads, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: any, TargetFilename matches *.hta in %TEMP% or %USERPROFILE%\Downloads, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: any, TargetFilename matches *.js in %TEMP% or %USERPROFILE%\Downloads, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: any, TargetFilename matches *.txt, *.cer, *.enc, *.b64, *.zip in any directory, CreationUtcTime: any | Source: T1140  
[BEHAVIOR] Image: any, TargetFilename matches *.zip, *.7z, *.enc in any directory, CreationUtcTime: any | Source: T1027  

**Explanation of omitted items**  
- The vulnerability CVE‑2023‑27350 is a remote authentication bypass that leads to arbitrary code execution. Sysmon EventID 11 only records file‑creation activity and does not capture the network authentication step or the subsequent in‑memory code execution, so no monitoring recommendation for this CVE can be expressed using this event type. Consequently, it is omitted from the list.