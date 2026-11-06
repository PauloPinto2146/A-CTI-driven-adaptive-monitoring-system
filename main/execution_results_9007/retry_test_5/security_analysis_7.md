[IOC] ImageLoaded hash 6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141 (filename x86_64-unknown-linux-esxi.elf) | Source: IOC‑hash‑6cd349e  
[IOC] ImageLoaded hash acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4 (filename h3odp7l2u.exe) | Source: IOC‑hash‑acce811c  
[IOC] ImageLoaded hash 31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502 (filename hi9lezv.exe) | Source: IOC‑hash‑3180038  
[IOC] ImageLoaded hash 1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449 (filename 072wiof7.exe) | Source: IOC‑hash‑1898d05  
[IOC] ImageLoaded hash 1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11 (filename k0d649u.exe) | Source: IOC‑hash‑1d10d8f  
[IOC] ImageLoaded hash 24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7 (filename 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt‑strike_glassworm_poet‑rat) | Source: IOC‑hash‑24f6c0c  
[IOC] ImageLoaded hash 589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880 (filename 2qfguc.exe) | Source: IOC‑hash‑589d948  
[IOC] ImageLoaded hash 5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241 (filename 7hhel.exe) | Source: IOC‑hash‑5cc212f  
[IOC] ImageLoaded hash 60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6 (filename 3ctjhm3.exe) | Source: IOC‑hash‑60aeb9f  
[IOC] ImageLoaded hash 6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f (filename 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt‑strike_glassworm_poet‑rat) | Source: IOC‑hash‑6bf155b  
[IOC] ImageLoaded hash 765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a (filename bjiw49.exe) | Source: IOC‑hash‑765508a  
[IOC] ImageLoaded hash 7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245 (filename 7l73h.exe) | Source: IOC‑hash‑7f37351  
[IOC] ImageLoaded hash 8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4 (filename 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt‑strike_glassworm_poet‑rat) | Source: IOC‑hash‑8d1a22c  
[IOC] ImageLoaded hash 90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c (filename 0m6m882x2.exe) | Source: IOC‑hash‑90e46e8  
[IOC] ImageLoaded hash 97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2 (filename inc.exe) | Source: IOC‑hash‑97aebda  
[IOC] ImageLoaded hash bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc (filename 61pd6n3t.exe) | Source: IOC‑hash‑bf8c45e  
[IOC] ImageLoaded hash d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570 (filename mk1yd.exe) | Source: IOC‑hash‑d26bfb0  
[IOC] ImageLoaded hash d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb (filename a3mnw9.exe) | Source: IOC‑hash‑d651202  
[IOC] ImageLoaded hash dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da (filename win.bin) | Source: IOC‑hash‑dc9938f  
[IOC] ImageLoaded hash ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22 (filename vw06lg0y.exe) | Source: IOC‑hash‑ea72124  
[IOC] ImageLoaded hash f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347 (filename qgp2s6z.exe) | Source: IOC‑hash‑f6a01d0  
[IOC] ImageLoaded hash ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b (filename tt24n8xsl.exe) | Source: IOC‑hash‑ff5da8f  

[BEHAVIOR] Image: w3wp.exe (IIS worker process) loading any non‑system ImageLoaded module (e.g., DLL or EXE not located in %SystemRoot%\\System32) | Source: T1190  

[BEHAVIOR] Image: any public‑facing service process (e.g., httpd.exe, nginx.exe, svchost.exe when hosting a web API) loading a module whose Signed status is “Unsigned” or SignatureStatus is “Invalid” | Source: T1190  

[DERIVED] ImageLoaded modules that are signed by a signer not associated with Microsoft, Microsoft Windows, or the legitimate vendor of the parent process (as indicated by the Signature field) – indicative of malicious loaders after exploitation of CVE‑2023‑3519 or CVE‑2023‑48788 | Source: CVE‑2023‑3519  

[DERIVED] ImageLoaded modules whose FileVersion or Product fields are missing or contain atypical values for the parent process (e.g., a web server loading a module whose Product does not match “Microsoft IIS” or the vendor of the server) – potential payload drop following exploitation of CVE‑2024‑57727 or CVE‑2025‑5777 | Source: CVE‑2024‑57727  