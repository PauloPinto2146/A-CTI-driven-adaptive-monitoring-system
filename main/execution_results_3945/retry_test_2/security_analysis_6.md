[BEHAVIOR] ImageLoaded:*.sys | Signed:false | SignatureStatus:Unsigned | Source: T1543.003  
[BEHAVIOR] ImageLoaded:*.sys | SignatureStatus:Invalid | Source: T1543.003  
[BEHAVIOR] ImageLoaded:*.sys | Signed:true | Signature:* | Source: T1543.003 (monitor for unexpected or unknown signer)  
[DERIVED] ImageLoaded:C:\Users\* | Source: T1543.003 (drivers loaded from user profile directories are atypical)  
[DERIVED] ImageLoaded:C:\Temp\* | Source: T1543.003 (drivers loaded from temporary directories are suspicious)  
[DERIVED] ImageLoaded:* | Signed:false | Source: T1543.003 (detect unsigned driver loads indicative of malicious driver installation)  

**Explanation of omitted IoCs:**  
The provided indicators of compromise (wiseman.EXE SHA‑256 ebba8f4342b… and wininet.dll SHA‑256 fda9864b1aa…) refer to an executable and a DLL, not to driver files (.sys). Sysmon Event ID 6 records driver‑load events and does not capture ordinary executable or DLL loads, so these specific IoCs cannot be observed with this event type and were therefore excluded from the recommendations.  

**Explanation of omitted attack pattern:**  
The attack pattern T1543.003 (Windows Service) is retained because it explicitly mentions the loading of malicious drivers via service creation, which is directly observable through driver‑load events. No other attack patterns were omitted.