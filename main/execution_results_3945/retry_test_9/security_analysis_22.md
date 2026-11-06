[IOC] Image == "wiseman.exe" | Source: wiseman.EXE  
[BEHAVIOR] Image == "rundll32.exe" | Source: T1218.011  
[BEHAVIOR] Image in ("powershell.exe", "python.exe") | Source: T1071.004  
[BEHAVIOR] QueryName length > 50 characters (potential base64/base32 payload) | Source: T1071.004  
[BEHAVIOR] QueryName matches typical DNS tunneling patterns (e.g., long subdomains, encoded strings) | Source: T1071.004  
[BEHAVIOR] Image == "mstsc.exe" OR Image == "ssh.exe" | Source: T1021  
[BEHAVIOR] Image == "net.exe" OR Image == "ping.exe" | Source: T1018  
[BEHAVIOR] DNS queries directed to IP ranges outside the organization’s internal subnet (anomalous external destinations) | Source: T1218.011  

**Explanation of omitted items**  
- **wininet.dll**: This is a DLL, not a process executable, and Event ID 22 records only the Image (process) that initiates the DNS query. Since Sysmon does not log the specific DLLs a process has loaded, wininet.dll cannot be directly observed with this event type.  
- **T1102.001 (Dead Drop Resolver)**: The technique involves retrieving payloads from web services over HTTP/HTTPS, not DNS. Event ID 22 captures DNS queries only, so there is no concrete DNS‑related observable tied to this technique in the provided data.  
- **CVE‑2023‑27350**: The vulnerability pertains to authentication bypass and arbitrary code execution in PaperCut NG; no DNS‑specific indicators (domains, query patterns, or processes) are described. Consequently, no Sysmon 22‑compatible recommendation can be derived from the CVE description.  