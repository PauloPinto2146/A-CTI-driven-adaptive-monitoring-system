[IOC] Monitor any process loading an image whose SHA‑256 hash is **ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205** (wiseman.EXE) | Source: IOC sha256:ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  

[IOC] Monitor any process loading an image whose SHA‑256 hash is **fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c** (wininet.dll) | Source: IOC sha256:fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c  

[BEHAVIOR] Monitor **rundll32.exe** loading modules with a **.cpl** extension (Control Panel Item files) | Source: T1218.011  

[BEHAVIOR] Monitor **rundll32.exe** loading modules with **.js**, **.sct**, **.hta**, or **.cpl** extensions via the undocumented `Control_RunDLL` or `RunHTMLApplication` functions | Source: T1218.011  

[BEHAVIOR] Monitor **rundll32.exe** loading modules that are not on the environment‑specific baseline “AllowedDLLs” list (i.e., uncommon or unexpected DLLs) | Source: T1218.011  

[DERIVED] Monitor **cmd.exe** loading modules from writable or user‑accessible locations (e.g., %TEMP%, C:\Users\Public, external drives) | Source: T1059.003  

[DERIVED] Monitor any process (especially rundll32.exe or cmd.exe) loading a module that is **unsigned** or whose signature status is not “Valid” (e.g., SignatureStatus = “Invalid”, “Unknown”) | Source: T1218.011, T1059.003