[IOC] Image=* | TargetFilename=wiseman.EXE | Hashes=ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 | IsExecutable=True | Archived=True | Source: IoC-wiseman.EXE  
[IOC] Image=* | TargetFilename=wininet.dll | Hashes=fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c | IsExecutable=False | Archived=True | Source: IoC-wininet.dll  
[BEHAVIOR] Image=*del* OR Image=*erase* OR Image=*sdelete* | TargetFilename=* | Hashes=* | IsExecutable=* | Archived=* | Source: T1070.004  
[DERIVED] Archived=True | Source: T1070.004  

**Explanation:** The vulnerability CVE‑2023‑27350 pertains to authentication bypass and remote code execution on PaperCut NG and does not involve file deletion activity observable via Sysmon Event ID 23; therefore it was excluded from these monitoring recommendations.