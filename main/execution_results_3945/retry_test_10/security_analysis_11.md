[IOC] Image: *, TargetFilename: wiseman.EXE, CreationUtcTime: * | Source: filename wiseman.EXE  
[IOC] Image: *, TargetFilename: wininet.dll, CreationUtcTime: * | Source: filename wininet.dll  

[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.dll, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.cpl, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.sct, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.hta, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.js, CreationUtcTime: * | Source: T1218.011  

[BEHAVIOR] Image: *\certutil.exe, TargetFilename: *.exe, CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *\powershell.exe, TargetFilename: *.exe, CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *\copy.exe, TargetFilename: *.exe, CreationUtcTime: * | Source: T1140  

[BEHAVIOR] Image: *, TargetFilename: *.zip, CreationUtcTime: * | Source: T1027  
[BEHAVIOR] Image: *, TargetFilename: *.7z, CreationUtcTime: * | Source: T1027  
[BEHAVIOR] Image: *, TargetFilename: *.enc, CreationUtcTime: * | Source: T1027  

**Explanation of omitted items**  
- **CVE‑2023‑27350**: The vulnerability description does not specify any particular file creation activity, filenames, or directories that would be observable via Sysmon Event ID 11. Without a concrete file‑related indicator, no monitoring recommendation can be justified for this CVE based on the allowed event type.  
- No additional IoCs beyond the two filenames provided were present; therefore no further IOC‑based recommendations are included.