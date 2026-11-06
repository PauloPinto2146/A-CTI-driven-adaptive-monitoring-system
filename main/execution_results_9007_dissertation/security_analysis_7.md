[IOC] ImageLoaded SHA256=6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141 Filename=x86_64-unknown-linux-esxi.elf | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4 Filename=h3odp7l2u.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502 Filename=hi9lezv.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449 Filename=072wiof7.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11 Filename=k0d649u.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7 Filename=2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880 Filename=2qfguc.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241 Filename=7hhel.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6 Filename=3ctjhm3.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f Filename=2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a Filename=bjiw49.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245 Filename=7l73h.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4 Filename=2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c Filename=0m6m882x2.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2 Filename=inc.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc Filename=61pd6n3t.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570 Filename=mk1yd.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb Filename=a3mnw9.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da Filename=win.bin | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22 Filename=vw06lg0y.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347 Filename=qgp2s6z.exe | Source: IOC (hash)  
[IOC] ImageLoaded SHA256=ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b Filename=tt24n8xsl.exe | Source: IOC (hash)  

[BEHAVIOR] Monitor any unsigned or poorly signed module loaded by the IIS worker process (w3wp.exe) following a spike in HTTP 4xx/5xx responses, indicating possible exploitation of a public‑facing application | Source: T1190 (AN0219)  

[BEHAVIOR] Monitor loading of modules that are not in the known allowed child list (e.g., msbuild.exe, other legitimate child processes) by server‑side processes such as w3wp.exe, svchost.exe, or other public‑facing services | Source: T1190 (AN0219)  

[DERIVED] Monitor loading of modules from temporary or user‑writable directories (e.g., %TEMP%, %TMP%, /tmp) by any process shortly after a network request that could be related to CVE‑2023‑3519 exploitation, as attackers may drop payloads there before execution | Source: CVE-2023-3519  

[DERIVED] Monitor loading of modules located in paths writable by the FortiClientEMS service after receipt of specially crafted packets, to detect exploitation of CVE‑2023‑48788 (SQL‑injection‑based code execution) | Source: CVE-2023-48788  

[DERIVED] Monitor loading of modules that originate from paths traversed via crafted HTTP requests (e.g., attempts to access configuration files) as part of the exploitation chain for CVE‑2024‑57727, focusing on any file load that reads configuration or password files | Source: CVE-2024-57727  

[DERIVED] Monitor loading of modules by NetScaler processes (e.g., ns-cmp.exe, ns-svrcore.exe) that exhibit memory over‑read patterns after configuration of VPN or RDP virtual servers, indicative of CVE‑2025‑5777 exploitation | Source: CVE-2025-5777