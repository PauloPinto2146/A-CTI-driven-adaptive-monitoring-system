[IOC] Image: *, TargetFilename: wiseman.EXE, CreationUtcTime: * | Source: IOC filename wiseman.EXE  
[IOC] Image: *, TargetFilename: wininet.dll, CreationUtcTime: * | Source: IOC filename wininet.dll  

[BEHAVIOR] Image: *, TargetFilename: *.cpl, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *, TargetFilename: *.dll, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *, TargetFilename: *.js, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *, TargetFilename: *.sct, CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: *, TargetFilename: *.hta, CreationUtcTime: * | Source: T1218.011  

[BEHAVIOR] Image: *, TargetFilename: *.txt, CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *, TargetFilename: *.cer, CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *, TargetFilename: *.enc, CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: *, TargetFilename: *.b64, CreationUtcTime: * | Source: T1140  

[BEHAVIOR] Image: *, TargetFilename: *.zip, CreationUtcTime: * | Source: T1027  
[BEHAVIOR] Image: *, TargetFilename: *.7z, CreationUtcTime: * | Source: T1027  

[DERIVED] Image: *, TargetFilename: *\\Temp\\*, CreationUtcTime: * | Source: T1218.011 (rundll32 frequently drops payloads in temporary directories)  

---  
**Explanation of omitted items**  
- The vulnerability CVE‑2023‑27350 is unrelated to file‑creation activity; it describes an authentication bypass in PaperCut NG and does not specify any file or DLL that would be created by the exploit. Therefore it is not included in the Sysmon Event ID 11 recommendations.  
- No attack patterns or IoCs were omitted: all provided filenames (wiseman.EXE, wininet.dll) and all listed ATT&CK techniques (T1218.011, T1140, T1027) have at least one corresponding monitoring recommendation above.