[IOC] Image: * TargetFilename: wiseman.EXE CreationUtcTime: * | Source: filename wiseman.EXE  
[IOC] Image: * TargetFilename: wininet.dll CreationUtcTime: * | Source: filename wininet.dll  
[BEHAVIOR] Image: *rundll32.exe* TargetFilename: *.dll* CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *rundll32.exe* TargetFilename: *.cpl* CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *rundll32.exe* TargetFilename: *.sct* CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *rundll32.exe* TargetFilename: *.hta* CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *certutil.exe* TargetFilename: *.cer* CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *powershell.exe* TargetFilename: *.b64* CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *copy.exe* TargetFilename: *.txt* CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *powershell.exe* TargetFilename: *.zip* CreationUtcTime: * | Source: T1027  
[DERIVED] Image: * TargetFilename: *.dll* CreationUtcTime: * | Source: CVE-2023-27350 (monitor creation of DLLs in system or autostart locations by non‑trusted processes)  
[DERIVED] Image: * TargetFilename: *.* CreationUtcTime: * | Source: CVE-2023-27350 (monitor file creation in typical autostart folders such as Startup or Run keys)  