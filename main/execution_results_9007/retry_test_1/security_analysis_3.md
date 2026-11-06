[IOC] Image == “x86_64-unknown-linux-esxi.elf” | Source: sha256 6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141  
[IOC] Image == “h3odp7l2u.exe” | Source: sha256 acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4  
[IOC] Image == “hi9lezv.exe” | Source: sha256 31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502  
[IOC] Image == “072wiof7.exe” | Source: sha256 1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449  
[IOC] Image == “k0d649u.exe” | Source: sha256 1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11  
[IOC] Image == “2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat.exe” | Source: sha256 24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7  
[IOC] Image == “2qfguc.exe” | Source: sha256 589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880  
[IOC] Image == “7hhel.exe” | Source: sha256 5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241  
[IOC] Image == “3ctjhm3.exe” | Source: sha256 60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6  
[IOC] Image == “2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat.exe” | Source: sha256 6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f  
[IOC] Image == “bjiw49.exe” | Source: sha256 765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a  
[IOC] Image == “7l73h.exe” | Source: sha256 7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245  
[IOC] Image == “2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat.exe” | Source: sha256 8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4  
[IOC] Image == “0m6m882x2.exe” | Source: sha256 90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c  
[IOC] Image == “inc.exe” | Source: sha256 97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2  
[IOC] Image == “61pd6n3t.exe” | Source: sha256 bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc  
[IOC] Image == “mk1yd.exe” | Source: sha256 d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570  
[IOC] Image == “a3mnw9.exe” | Source: sha256 d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb  
[IOC] Image == “win.bin” | Source: sha256 dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da  
[IOC] Image == “vw06lg0y.exe” | Source: sha256 ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22  
[IOC] Image == “qgp2s6z.exe” | Source: sha256 f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347  
[IOC] Image == “tt24n8xsl.exe” | Source: sha256 ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b  
[IOC] DestinationHostname == “incblog.su” | Source: domain incblog.su  
[IOC] DestinationHostname == “incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion” | Source: domain incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion  
[IOC] DestinationHostname == “incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion” | Source: domain incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion  

[BEHAVIOR] Protocol == “SMB” AND DestinationPort == 445 AND Initiated == true | Source: T1021.002  
[BEHAVIOR] Protocol == “RDP” AND DestinationPort == 3389 AND Initiated == true | Source: T1021.001  
[BEHAVIOR] Protocol == “DNS” AND DestinationPort == 53 AND Initiated == true | Source: T1557  
[BEHAVIOR] Protocol == “HTTP” OR Protocol == “HTTPS” AND Initiated == true | Source: T1071  
[DERIVED] Protocol in (“HTTP”, “HTTPS”) AND DestinationHostname matches known cloud‑storage services (e.g., “*.dropbox.com”, “*.drive.google.com”, “*.onedrive.com”) AND Initiated == true | Source: T1567  
[DERIVED] Initiated == true AND DestinationIp is external (outside corporate CIDR) AND DestinationPort not in common allowlist (e.g., 80,443,53,445,3389) | Source: T1018 (remote system discovery)  
[DERIVED] Initiated == true AND DestinationPort == 0 (failed DNS resolution) AND Image matches any of the malicious filenames above | Source: T1569.002 (service execution of malicious payloads)  