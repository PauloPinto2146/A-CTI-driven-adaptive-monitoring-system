[IOC] Monitor creation of a file named **wiseman.EXE** (any path) | Source: filename wiseman.EXE  
[IOC] Monitor creation of a file named **wininet.dll** (any path) | Source: filename wininet.dll  
[BEHAVIOR] Monitor file creation where the creating process is **rundll32.exe** and the target filename ends with **.dll** | Source: T1218.011  
[BEHAVIOR] Monitor file creation where the creating process is **rundll32.exe** and the target filename ends with **.cpl** | Source: T1218.011  
[BEHAVIOR] Monitor file creation where the creating process is **rundll32.exe** and the target filename ends with **.sct** or **.hta** | Source: T1218.011  
[BEHAVIOR] Monitor file creation where the creating process is **certutil.exe**, **powershell.exe**, or **copy.exe** and the target filename ends with **.txt**, **.cer**, **.enc**, **.b64**, **.zip**, or **.7z** | Source: T1140, T1027