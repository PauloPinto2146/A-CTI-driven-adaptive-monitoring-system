[IOC] ImageLoaded SHA256 = fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c (wininet.dll) | Source: fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c  
[IOC] Image SHA256 = ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (wiseman.EXE) | Source: ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  
[BEHAVIOR] Image = *\rundll32.exe loading ImageLoaded with extensions .dll, .cpl, .sct, .hta, .js | Source: T1218.011  
[BEHAVIOR] Image = *\rundll32.exe loading ImageLoaded where Signed = false OR SignatureStatus != "Valid" | Source: T1218.011  
[DERIVED] Image = *\cmd.exe loading ImageLoaded from %TEMP% or C:\Users\Public\ directories | Source: T1059.003  
[DERIVED] Image path containing “PaperCut” loading any ImageLoaded where Signed = false | Source: CVE-2023-27350