[IOC] Image: * | TargetFilename: wiseman.EXE | CreationUtcTime: * | Source: filename:wiseman.EXE  
[IOC] Image: * | TargetFilename: wininet.dll | CreationUtcTime: * | Source: filename:wininet.dll  
[BEHAVIOR] Image: *rundll32.exe* | TargetFilename: *.dll | CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *rundll32.exe* | TargetFilename: *.cpl | CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *rundll32.exe* | TargetFilename: *.sct | CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *rundll32.exe* | TargetFilename: *.hta | CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: * | TargetFilename: *.txt | CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: * | TargetFilename: *.cer | CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: * | TargetFilename: *.b64 | CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: * | TargetFilename: *.zip | CreationUtcTime: * | Source: T1027  
[BEHAVIOR] Image: * | TargetFilename: *.7z | CreationUtcTime: * | Source: T1027  
[BEHAVIOR] Image: * | TargetFilename: *.enc | CreationUtcTime: * | Source: T1027  

**Explanation of omitted items**  
- **CVE‑2023‑27350**: The vulnerability pertains to an authentication bypass in PaperCut NG and results in remote code execution via network interaction. It does not involve the creation or overwriting of files on the host, which is the only activity captured by Sysmon Event ID 11. Consequently, no file‑creation‑specific monitoring recommendation can be derived from this CVE, so it is excluded from the analysis.