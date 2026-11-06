[BEHAVIOR] ImageLoaded ends with “.sys” | Source: T1543.003  
[BEHAVIOR] Signed == false (unsigned driver loaded) | Source: T1543.003  
[BEHAVIOR] SignatureStatus != “Valid” (driver signature invalid or missing) | Source: T1543.003  
[BEHAVIOR] ImageLoaded path resides in uncommon directories (e.g., C:\Users\, C:\Temp\, C:\ProgramData\) | Source: T1543.003  

**Explanation for omitted IoCs**  
The provided indicators of compromise (wiseman.EXE and wininet.dll) are an executable and a DLL, not kernel‑mode drivers. Sysmon Event ID 6 records driver‑load events only for kernel drivers (typically *.sys files) and includes fields such as ImageLoaded, Hashes, Signed, Signature, and SignatureStatus. Because these IoCs are not driver files, they cannot be observed through Event ID 6, and thus they are not included in the recommendations.  

**Explanation for omitted attack pattern detail**  
The ATT&CK technique T1543.003 describes persistence via Windows services and mentions loading malicious drivers, but it does not provide concrete driver filenames or hashes. Consequently, the recommendations focus on observable driver‑load characteristics (file extension, signature status, and unusual load paths) rather than specific file names, which are not available in the supplied context.