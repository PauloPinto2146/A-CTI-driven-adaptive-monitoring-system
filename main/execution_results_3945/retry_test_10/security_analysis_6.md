[BEHAVIOR] ImageLoaded: path contains “C:\Users\” or “C:\Temp\” ; Signed: false ; SignatureStatus: not‑valid | Source: T1543.003  
[BEHAVIOR] ImageLoaded: filename matches suspicious service‑driver patterns (e.g., `svhostx.sys`, `winhelp.sys`, `*service*.sys`) ; Signed: false ; SignatureStatus: not‑valid | Source: T1543.003  
[BEHAVIOR] ImageLoaded: any *.sys driver loaded ; Signed: false ; SignatureStatus: not‑valid | Source: T1543.003  

**Explanation of omitted items**  
- The provided IOC hashes (`wiseman.EXE` SHA‑256 = ebba8f4342b… and `wininet.dll` SHA‑256 = fda9864b1a…) refer to an executable and a DLL, not to a driver file (*.sys). Sysmon Event ID 6 only records driver loads, so these hashes cannot be observed with this event type and are therefore excluded.  
- CVE‑2023‑27350 describes a remote authentication‑bypass vulnerability in PaperCut NG that leads to arbitrary code execution as SYSTEM. The vulnerability does not specify loading a malicious driver, nor does it provide driver‑related artifacts (path, hash, signature). Consequently, there is no driver‑load indicator to monitor via Event ID 6, so this CVE is not represented in the recommendations.  