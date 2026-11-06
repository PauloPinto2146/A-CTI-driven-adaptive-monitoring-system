[IOC] Image: * | TargetFilename: *wiseman.EXE* | Hashes: ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | IsExecutable: true | Archived: true | Source: IOC:wizeman.EXE hash  

[IOC] Image: * | TargetFilename: *wininet.dll* | Hashes: fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | IsExecutable: false | Archived: true | Source: IOC:wininet.dll hash  

[BEHAVIOR] Image: *\sdelete.exe* | TargetFilename: * | Hashes: * | IsExecutable: true | Archived: true | Source: T1070.004  

[BEHAVIOR] Image: *\cmd.exe* | TargetFilename: C:\Windows\Temp\* | Hashes: * | IsExecutable: false | Archived: true | Source: T1070.004  

[DERIVED] Image: *\svchost.exe* | TargetFilename: * | Hashes: * | IsExecutable: true | Archived: true | Source: CVE-2023-27350