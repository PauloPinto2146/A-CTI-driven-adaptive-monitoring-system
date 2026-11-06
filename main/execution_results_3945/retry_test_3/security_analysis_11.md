[IOC] Image: *\* (any process), TargetFilename: wiseman.EXE, CreationUtcTime: any | Source: wiseman.EXE  
[IOC] Image: *\* (any process), TargetFilename: wininet.dll, CreationUtcTime: any | Source: wininet.dll  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.dll, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.cpl, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.js;*.sct;*.hta, CreationUtcTime: any | Source: T1218.011  
[BEHAVIOR] Image: *\certutil.exe, TargetFilename: *.cer;*.b64;*.enc;*.txt;*.zip;*.7z, CreationUtcTime: any | Source: T1140  
[BEHAVIOR] Image: *\powershell.exe, TargetFilename: *.b64;*.enc;*.txt;*.zip;*.7z, CreationUtcTime: any | Source: T1027  
[BEHAVIOR] Image: *\copy.exe, TargetFilename: *.b64;*.enc;*.txt;*.zip;*.7z, CreationUtcTime: any | Source: T1027  
[DERIVED] Image: *\PaperCut\* (any process in PaperCut NG installation directory), TargetFilename: *.exe;*.dll, CreationUtcTime: any | Source: CVE-2023-27350