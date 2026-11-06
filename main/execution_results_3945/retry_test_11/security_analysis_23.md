[IOC] Image: *any* | TargetFilename: “wiseman.EXE” | Hashes: ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | IsExecutable: true | Archived: true | Source: IOC‑wiseman.EXE  

[IOC] Image: *any* | TargetFilename: “wininet.dll” | Hashes: fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | IsExecutable: true | Archived: true | Source: IOC‑wininet.dll  

[BEHAVIOR] Image: *sdelete.exe* | TargetFilename: *any* | IsExecutable: true | Archived: *as configured* | Source: T1070.004  

[BEHAVIOR] Image: *cmd.exe* or *powershell.exe* | TargetFilename: *any* | IsExecutable: true | Archived: *as configured* | Source: T1070.004  

[DERIVED] UserContext: SYSTEM | Image: *any* | TargetFilename: *any* | IsExecutable: *as applicable* | Archived: *as configured* | Source: CVE‑2023‑27350