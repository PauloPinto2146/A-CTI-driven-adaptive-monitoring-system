[IOC] Image: * (any process), TargetFilename: wiseman.EXE | Source: IOC filename wiseman.EXE  
[IOC] Image: * (any process), TargetFilename: wininet.dll | Source: IOC filename wininet.dll  
[BEHAVIOR] Image: *\rundll32.exe, TargetFilename: *.dll or *.cpl (any location) | Source: T1218.011  
[BEHAVIOR] Image: *\certutil.exe, TargetFilename: *.txt, *.cer, *.enc, *.b64, *.zip, *.sct, *.hta (any location) | Source: T1140  
[BEHAVIOR] Image: *\powershell.exe, TargetFilename: *.ps1, *.psm1, *.txt, *.zip, *.enc (any location) | Source: T1140  
[BEHAVIOR] Image: *\copy.exe, TargetFilename: *.txt, *.b64, *.enc, *.zip (any location) | Source: T1140  
[DERIVED] Image: * (any process), TargetFilename: * (any file) created in known drop locations such as %TEMP%, %USERPROFILE%\Downloads, or the Startup folder | Source: T1218.011, T1027  
[DERIVED] Image: * (any process), TargetFilename: *.exe created in C:\Windows\System32 or C:\Program Files\PaperCut* directories | Source: CVE-2023-27350  

**Explanation of omitted items:**  
All provided IOC filenames (wiseman.EXE, wininet.dll) and all three ATT&CK techniques (T1218.011, T1140, T1027) have been incorporated into the recommendations above. No indicator or technique was omitted.