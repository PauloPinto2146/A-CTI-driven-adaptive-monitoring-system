[IOC] Image ends with “wiseman.exe” | Source: SHA256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205 (wiseman.EXE)  
[BEHAVIOR] Image ends with “rundll32.exe” AND DestinationPort = 53 AND Protocol = UDP | Source: T1071.004 (DNS Tunneling)  
[BEHAVIOR] Image ends with “rundll32.exe” AND DestinationIp is external (not in internal corporate ranges) | Source: T1218.011 (Rundll32 Abuse)  
[BEHAVIOR] DestinationPort = 3389 OR DestinationPort = 22 OR DestinationPort = 445 AND Initiated = true AND Image NOT IN {“svchost.exe”, “lsass.exe”, “services.exe”} | Source: T1021 (Remote Services)  
[BEHAVIOR] Image ends with “net.exe” OR Image ends with “ping.exe” OR Image ends with “tracert.exe” AND Initiated = true | Source: T1018 (Remote System Discovery)  
[BEHAVIOR] DestinationHostname = “pastebin.com” OR DestinationHostname = “twitter.com” | Source: T1102.001 (Dead‑Drop Resolver)  

**Omitted items and rationale**  
- The IOC wininet.dll (SHA256 fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c) is not included because Sysmon Event ID 3 records the *process* that initiates a network connection, not the DLLs that the process loads; the DLL name therefore cannot be observed directly from this event type.  
- CVE‑2023‑27350 (PaperCut NG authentication bypass) is omitted because the vulnerability is a server‑side privilege‑escalation issue that does not manifest as a distinctive local network‑connection pattern that can be captured by Sysmon Event ID 3.  
- The remaining attack patterns (T1218.011, T1071.004, T1021, T1018, T1102.001) are represented only by the behavior‑based recommendations above; no concrete values (e.g., specific ports, domains, or filenames other than those already listed) were provided in the threat data, so no additional IOC‑level rules could be derived for this event type.