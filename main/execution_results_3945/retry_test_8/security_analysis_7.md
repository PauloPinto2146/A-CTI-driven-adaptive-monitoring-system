[IOC] ImageLoaded SHA256 equals ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (wiseman.EXE) | Source: sha256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  

[IOC] ImageLoaded SHA256 equals fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c (wininet.dll) | Source: sha256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c  

[BEHAVIOR] Image = *\rundll32.exe AND ImageLoaded extension is .dll, .cpl, or starts with “javascript:” (indicative of Rundll32 abuse) | Source: T1218.011  

[BEHAVIOR] Image = *\rundll32.exe AND ImageLoaded resides outside of the baseline AllowedDLLs list (suspicious DLL/CPL load) | Source: T1218.011  

[DERIVED] Image = *\rundll32.exe AND Signed = false OR SignatureStatus ≠ “Valid” (unsigned or improperly signed modules loaded by Rundll32) | Source: T1218.011  

[DERIVED] Image = *\rundll32.exe AND ImageLoaded is fetched from a remote URL or UNC path (e.g., loading .sct, .hta, or other script files) | Source: T1218.011  

[DERIVED] Image = *\cmd.exe AND ImageLoaded is a DLL that is not commonly loaded by cmd.exe (e.g., non‑system DLLs) | Source: T1059.003  

**Omitted items explanation:**  
- CVE‑2023‑27350 was not included because the vulnerability description involves a web‑application authentication bypass and arbitrary code execution via the PaperCut service, which does not manifest as a specific module load observable through Sysmon Event ID 7.  
- No additional IoCs beyond the two provided hashes/filenames were considered, as no further concrete values were present in the supplied threat data.  