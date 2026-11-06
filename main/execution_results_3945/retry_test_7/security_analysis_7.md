[IOC] Monitor Image == "wiseman.EXE" and capture full ImageLoaded record (ImageLoaded, FileVersion, Product, Company, OriginalFileName, Hashes, Signed, Signature, SignatureStatus) for any module it loads. | Source: IoC filename wiseman.EXE  

[IOC] Monitor ImageLoaded == "wininet.dll" with SHA256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c and capture full ImageLoaded record (Image, FileVersion, Product, Company, OriginalFileName, Hashes, Signed, Signature, SignatureStatus). | Source: IoC sha256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c  

[BEHAVIOR] Monitor Image == "rundll32.exe" loading any .dll, .cpl, or javascript: modules (ImageLoaded matching *.dll, *.cpl, javascript:*), capturing full ImageLoaded record (Image, ImageLoaded, FileVersion, Product, Company, OriginalFileName, Hashes, Signed, Signature, SignatureStatus). | Source: T1218.011  

[BEHAVIOR] Monitor Image == "cmd.exe" loading any module (ImageLoaded), capturing full ImageLoaded record (Image, ImageLoaded, FileVersion, Product, Company, OriginalFileName, Hashes, Signed, Signature, SignatureStatus). | Source: T1059.003  

**Omitted CVE-2023-27350** – This vulnerability concerns an authentication bypass and remote code execution via a web‑application component; Sysmon Event ID 7 logs only module load events and does not provide visibility into authentication or network‑based exploitation steps, so it cannot be observed with this event type.