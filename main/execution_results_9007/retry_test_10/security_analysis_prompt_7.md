
.Context:
	Attack pattern context: ['\n    The attack pattern T1190-Exploit Public-Facing Application is described as:\n    "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.\n\nExploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Stealth](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).\n\nIf an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.\n\nAdversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)\n\nFor websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25)"\n            \n\n            The attack pattern T1190 is detected using DET0080 (Exploit Public-Facing Application – multi-signal correlation (request → error → post-exploit process/egress)) which has the following Windows analytics associated:\n     - AN0219 descibed as: "Adversary sends crafted HTTP/S (or other service) input to an Internet-facing app (IIS/ASP.NET, API, device portal). Chain: (1) abnormal request patterns to public endpoint → (2) elevated 4xx/5xx or unusual methods/paths → (3) server process (w3wp.exe/other service) spawns shell/LOLbins or loads non-standard modules → (4) optional outbound callback from the host/container." with mutable elements:\n         . PublicVIPs: List of public IPs/hostnames that front apps; used to scope web log and Zeek/proxy data.\n         . SuspiciousPatterns: Regex set for exploit-like inputs (../, union select, cmd=, ${jndi:, rO0AB (Java serialization), %00, ${env:}, ${${::-j}ndi}).\n         . ErrorRateThreshold: Spike threshold for HTTP status 5xx/4xx per client or URI (e.g., >5 in 5m).\n         . TimeWindow: Correlation horizon between request, error, process spawn, and egress (e.g., 15 minutes).\n         . AllowedChildList: Known child processes of app pools (e.g., msbuild.exe in CI) to reduce false positives.\n']
	Vulnerability context: Known vulnerabilities:

- CVE-2023-3519: Unauthenticated remote code execution
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, HIGH on integrity, HIGH on availability

- CVE-2023-48788: A improper neutralization of special elements used in an sql command ('sql injection') in Fortinet FortiClientEMS version 7.2.0 through 7.2.2, FortiClientEMS 7.0.1 through 7.0.10 allows attacker to execute unauthorized code or commands via specially crafted packets.
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, HIGH on integrity, HIGH on availability

- CVE-2024-57727: SimpleHelp remote support software v5.5.7 and before is vulnerable to multiple path traversal vulnerabilities that enable unauthenticated remote attackers to download arbitrary files from the SimpleHelp host via crafted HTTP requests. These files include server configuration files containing various secrets and hashed user passwords.
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, NONE on integrity, NONE on availability

- CVE-2025-5777: Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server
  Attack vector: NETWORK; attack complexity: LOW; privileges required: NONE; user interaction: NONE
  Impact: HIGH on confidentiality, NONE on integrity, NONE on availability



.Task:
	Produce a Sysmon monitoring requirements analysis specifically for
	EventID 7: The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the "–l" option. It indicates the process in which the module is loaded, hashes and signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading. This event should be configured carefully, as monitoring all image load events will generate a significant amount of logging.



.Reported threat data:
	- Attack patterns: ['T1190']
	- Indicators of compromise: [{'sha256': '6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141', 'filename': 'x86_64-unknown-linux-esxi.elf'}, {'sha256': 'acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4', 'filename': 'h3odp7l2u.exe'}, {'sha256': '31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502', 'filename': 'hi9lezv.exe'}, {'sha256': '1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449', 'filename': '072wiof7.exe'}, {'sha256': '1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11', 'filename': 'k0d649u.exe'}, {'sha256': '24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7', 'filename': '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat'}, {'sha256': '589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880', 'filename': '2qfguc.exe'}, {'sha256': '5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241', 'filename': '7hhel.exe'}, {'sha256': '60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6', 'filename': '3ctjhm3.exe'}, {'sha256': '6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f', 'filename': '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat'}, {'sha256': '765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a', 'filename': 'bjiw49.exe'}, {'sha256': '7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245', 'filename': '7l73h.exe'}, {'sha256': '8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4', 'filename': '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat'}, {'sha256': '90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c', 'filename': '0m6m882x2.exe'}, {'sha256': '97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2', 'filename': 'inc.exe'}, {'sha256': 'bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc', 'filename': '61pd6n3t.exe'}, {'sha256': 'd26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570', 'filename': 'mk1yd.exe'}, {'sha256': 'd65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb', 'filename': 'a3mnw9.exe'}, {'sha256': 'dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da', 'filename': 'win.bin'}, {'sha256': 'ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22', 'filename': 'vw06lg0y.exe'}, {'sha256': 'f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347', 'filename': 'qgp2s6z.exe'}, {'sha256': 'ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b', 'filename': 'tt24n8xsl.exe'}]
	- Vulnerabilities: ['CVE-2023-3519', 'CVE-2023-48788', 'CVE-2024-57727', 'CVE-2025-5777']

.Requirements:
	1. Only recommend activity that this event type can record
	2. Avoid monitoring recommendations unrelated to the reported threat
	3. Include all information necessary to observe the reported activity, and nothing else
	4. Do not generate Sysmon configuration XML
	5. The output will be consumed by another LLM that generates the configuration, so be objective

.For each monitoring recommendation, identify its source using exactly one of these labels:

	[IOC]
	Use when the recommendation directly monitors a concrete value explicitly present in the provided threat intelligence, such as a filename, hash, IP address, domain, port, or registry value.
	Only use the exact values provided in the context.

	[BEHAVIOR]
	Use when the recommendation monitors behavior explicitly described by the provided ATT&CK or vulnerability context.
	Do not introduce concrete values that are not present in the provided context.

	[DERIVED]
	Use only when the recommendation is a reasonable monitoring consequence of the provided context but is not explicitly stated by an IoC, ATT&CK analytic, or vulnerability description.
	Do not introduce concrete values for DERIVED recommendations.

Each recommendation must be expressible with these fields:
	Image: File path of the process that loaded the image
ImageLoaded: Path of the image loaded
FileVersion: Version of the image loaded
Product: Product name the image loaded belongs to
Company: Company name the image loaded belongs to
OriginalFileName: OriginalFileName from the PE header, added on compilation
Hashes: Full hash of the file with the algorithms in the HashType field
Signed: State whether the image loaded is signed
Signature: The signer name
SignatureStatus: status of the signature
Every recommendation must be traceable to the provided context.
If a recommendation cannot be justified by the provided context, do not include it.

.Output format (plain text):
	One recommendation per line:
	[LABEL] <what to observe> | Source: <ATT&CK ID, CVE, or IoC key>
	If nothing in the context can be observed through this event type,
	output exactly: NO RECOMMENDATIONS

When omitting any indicator of compromise in [{'sha256': '6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141', 'filename': 'x86_64-unknown-linux-esxi.elf'}, {'sha256': 'acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4', 'filename': 'h3odp7l2u.exe'}, {'sha256': '31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502', 'filename': 'hi9lezv.exe'}, {'sha256': '1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449', 'filename': '072wiof7.exe'}, {'sha256': '1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11', 'filename': 'k0d649u.exe'}, {'sha256': '24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7', 'filename': '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat'}, {'sha256': '589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880', 'filename': '2qfguc.exe'}, {'sha256': '5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241', 'filename': '7hhel.exe'}, {'sha256': '60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6', 'filename': '3ctjhm3.exe'}, {'sha256': '6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f', 'filename': '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat'}, {'sha256': '765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a', 'filename': 'bjiw49.exe'}, {'sha256': '7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245', 'filename': '7l73h.exe'}, {'sha256': '8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4', 'filename': '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat'}, {'sha256': '90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c', 'filename': '0m6m882x2.exe'}, {'sha256': '97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2', 'filename': 'inc.exe'}, {'sha256': 'bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc', 'filename': '61pd6n3t.exe'}, {'sha256': 'd26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570', 'filename': 'mk1yd.exe'}, {'sha256': 'd65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb', 'filename': 'a3mnw9.exe'}, {'sha256': 'dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da', 'filename': 'win.bin'}, {'sha256': 'ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22', 'filename': 'vw06lg0y.exe'}, {'sha256': 'f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347', 'filename': 'qgp2s6z.exe'}, {'sha256': 'ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b', 'filename': 'tt24n8xsl.exe'}] and any attack pattern in ['T1190'], explain why it was not considered in the security analysis.
	
