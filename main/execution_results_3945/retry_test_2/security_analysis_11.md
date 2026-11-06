[IOC] Image: * TargetFilename: wiseman.EXE CreationUtcTime: * | Source: wiseman.EXE  
[IOC] Image: * TargetFilename: wininet.dll CreationUtcTime: * | Source: wininet.dll  
[BEHAVIOR] Image: * TargetFilename matches *.dll, *.cpl, *.sct, *.hta, *.js in user‑temp (%TEMP%), download (%USERPROFILE%\Downloads) or Startup directories (e.g., %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup) CreationUtcTime: * | Source: T1218.011  
[BEHAVIOR] Image: * TargetFilename matches *.txt, *.cer, *.enc, *.b64, *.zip, *.7z in any location shortly (≤ X seconds) after a network download or staging activity CreationUtcTime: * | Source: T1140  
[BEHAVIOR] Image: * TargetFilename matches *.zip, *.7z, *.enc with high entropy (indicating compression/encryption/obfuscation) CreationUtcTime: * | Source: T1027  

**Explanation of omitted items**  
- **CVE‑2023‑27350**: The vulnerability description pertains to authentication bypass and arbitrary code execution via a web‑application class, without mentioning file‑creation activity. EventID 11 records file create/overwrite events, so there is no direct observable artifact to monitor for this CVE using this event type. Consequently, no recommendation is provided for the CVE.  
- No additional IoCs or attack‑pattern details were omitted; all provided filenames and the three ATT&CK techniques (T1218.011, T1140, T1027) are represented in the recommendations above.