[IOC] Image=*; TargetFilename=wiseman.EXE; CreationUtcTime=* | Source: IOC wiseman.EXE  
[IOC] Image=*; TargetFilename=wininet.dll; CreationUtcTime=* | Source: IOC wininet.dll  
[BEHAVIOR] Image=*; TargetFilename=*.cpl; CreationUtcTime=* | Source: T1218.011 (Rundll32 abuse – Control Panel Item files)  
[BEHAVIOR] Image=*; TargetFilename=*.sct; CreationUtcTime=* | Source: T1218.011 (Rundll32 abuse – scriptlet files)  
[BEHAVIOR] Image=*; TargetFilename=*.hta; CreationUtcTime=* | Source: T1218.011 (Rundll32 abuse – HTML Application files)  
[BEHAVIOR] Image=*; TargetFilename=*.js; CreationUtcTime=* | Source: T1218.011 (Rundll32 abuse – JavaScript execution)  
[DERIVED] Image=*; TargetFilename=*.dll; CreationUtcTime=* (restricted to user‑writable locations such as %TEMP%, %APPDATA%) | Source: T1218.011 (potential DLL drop for later rundll32 loading)  
[BEHAVIOR] Image=*; TargetFilename=*.b64; CreationUtcTime=* | Source: T1140 (deobfuscation/decoding of files)  
[BEHAVIOR] Image=*; TargetFilename=*.enc; CreationUtcTime=* | Source: T1140 (deobfuscation/decoding of files)  
[BEHAVIOR] Image=*; TargetFilename=*.cer; CreationUtcTime=* | Source: T1140 (deobfuscation/decoding of files)  
[BEHAVIOR] Image=*; TargetFilename=*.txt; CreationUtcTime=* | Source: T1140 (deobfuscation/decoding of files)  
[BEHAVIOR] Image=*; TargetFilename=*.zip; CreationUtcTime=* | Source: T1027 (obfuscated/compressed payloads)  
[BEHAVIOR] Image=*; TargetFilename=*.7z; CreationUtcTime=* | Source: T1027 (obfuscated/compressed payloads)  
[DERIVED] Image=*; TargetFilename=*; CreationUtcTime=* (files created inside the PaperCut NG installation directory, e.g., C:\Program Files\PaperCut\) | Source: CVE-2023-27350 (malicious drop post‑authentication bypass)