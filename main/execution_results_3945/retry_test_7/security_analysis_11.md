[IOC] Image: * | TargetFilename: wiseman.EXE | CreationUtcTime: * | Source: IOC filename wiseman.EXE  
[IOC] Image: * | TargetFilename: wininet.dll | CreationUtcTime: * | Source: IOC filename wininet.dll  
[BEHAVIOR] Image: *rundll32.exe* | TargetFilename: *.dll | CreationUtcTime: * | Source: T1218.011 (Rundll32 abuse – loading of DLL payloads)  
[BEHAVIOR] Image: *rundll32.exe* | TargetFilename: *.cpl | CreationUtcTime: * | Source: T1218.011 (Rundll32 abuse – execution of Control Panel items)  
[BEHAVIOR] Image: *rundll32.exe* | TargetFilename: *.sct | CreationUtcTime: * | Source: T1218.011 (Rundll32 abuse – scriptlet execution)  
[BEHAVIOR] Image: *certutil.exe* | TargetFilename: *.b64 | CreationUtcTime: * | Source: T1140 (Deobfuscate/Decode Files – use of certutil to decode base64)  
[BEHAVIOR] Image: *certutil.exe* | TargetFilename: *.cer | CreationUtcTime: * | Source: T1140 (Deobfuscate/Decode Files – use of certutil to decode certificate files)  
[BEHAVIOR] Image: *powershell.exe* | TargetFilename: *.zip | CreationUtcTime: * | Source: T1027 (Obfuscated Files – creation of compressed archive payloads)  
[DERIVED] Image: * | TargetFilename: *.exe (created in known autostart locations such as %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup) | CreationUtcTime: * | Source: CVE-2023-27350 (Exploitation may drop a malicious executable for persistence)  