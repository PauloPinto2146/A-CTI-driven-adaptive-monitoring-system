[IOC] Image ends with “wiseman.exe” (any path) | Source: SHA256 ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205  
[BEHAVIOR] Image ends with “rundll32.exe” **and** Protocol is TCP or UDP **and** DestinationPort is 80, 443, **or** 53 (web or DNS) | Source: T1218.011  
[BEHAVIOR] Protocol is UDP **and** DestinationPort is 53 **and** Image is not a known legitimate DNS client (e.g., svchost.exe, dns.exe) | Source: T1071.004  
[BEHAVIOR] Protocol is TCP **and** DestinationPort is 3389 (RDP) **and** Initiated = true | Source: T1021  
[BEHAVIOR] Protocol is TCP **and** DestinationPort is 135 (WMI/DCOM) **and** Initiated = true | Source: T1021  
[DERIVED] DestinationPort is 445, 139, or 22 **and** multiple distinct DestinationIp values observed within a 30‑second window (burst of enumeration traffic) | Source: T1018  
[DERIVED] DestinationHostname is “pastebin.com” **or** “twitter.com” **and** Protocol is TCP **and** DestinationPort is 443 (HTTPS) | Source: T1102.001  