[IOC] Image=*; TargetFilename=*wiseman.EXE*; Hashes=ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205; IsExecutable=True; Archived=True | Source: IoC (wiseman.EXE)

[IOC] Image=*; TargetFilename=*wininet.dll*; Hashes=fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c; IsExecutable=False; Archived=True | Source: IoC (wininet.dll)

[BEHAVIOR] Image=*\\sdelete.exe*; TargetFilename=*; Hashes=*; IsExecutable=True; Archived=True | Source: T1070.004

[BEHAVIOR] Image=*\\cmd.exe*; TargetFilename=*; Hashes=*; IsExecutable=False; Archived=True | Source: T1070.004

[DERIVED] Image=*; TargetFilename=*; Hashes=*; IsExecutable=*; Archived=False | Source: T1070.004 (monitor deletions where archiving fails, indicating possible cleanup attempts without capture)