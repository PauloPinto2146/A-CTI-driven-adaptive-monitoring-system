
.Context:
	Attack pattern context: ['\n    The attack pattern T1219-Remote Access Tools is described as:\n    "An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network. Remote access tools create a session between two trusted hosts through a graphical interface, a command line interaction, a protocol tunnel via development or management software, or hardware-level access such as KVM (Keyboard, Video, Mouse) over IP solutions. Desktop support software (usually graphical interface) and remote management software (typically command line interface) allow a user to control a computer remotely as if they are a local user inheriting the user or software permissions. This software is commonly used for troubleshooting, software installation, and system management.(Citation: Symantec Living off the Land)(Citation: CrowdStrike 2015 Global Threat Report)(Citation: CrySyS Blog TeamSpy) Adversaries may similarly abuse response features included in EDR and other defensive tools that enable remote access.\n\nRemote access tools may be installed and used post-compromise as an alternate communications channel for redundant access or to establish an interactive remote desktop session with the target system. It may also be used as a malware component to establish a reverse connection or back-connect to a service or adversary-controlled system.\n\nInstallation of many remote access tools may also include persistence (e.g., the software\'s installation routine creates a [Windows Service](https://attack.mitre.org/techniques/T1543/003)). Remote access modules/features may also exist as part of otherwise existing software (e.g., Google Chrome’s Remote Desktop).(Citation: Google Chrome Remote Desktop)(Citation: Chrome Remote Desktop)"\n            \n\n            The attack pattern T1219 is detected using DET0496 (Behavior-Chain Detection for Remote Access Tools (Tool-Agnostic)) which has the following Windows analytics associated:\n     - AN1366 descibed as: "Chain of remote access tool behavior: (1) initial execution of remote-control/assist agent or GUI under user context; (2) persistence via service or autorun; (3) long-lived outbound connection/tunnel to external infrastructure; (4) interactive control signals such as shell or file-manager child processes spawned by the RAT parent." with mutable elements:\n         . TimeWindow: Correlation period binding start→persistence→egress→child (default 15m, adjust per environment).\n         . UserContext: Differentiate help-desk/jump hosts and admin accounts from standard endpoints.\n         . ProcessAllowlist: Known-good remote support tools; suppress expected events while still correlating anomalous sequences.\n         . InstallPathRegex: Alert when services/agents execute from user-writable or temp paths.\n         . ExternalIPAllowlist: Vendors’ support clouds/CDNs to reduce false positives on egress detection.\n         . ShellSpawnRegex: Define which child shells from GUI parents are acceptable versus suspicious.\n         . EgressHeuristics: Thresholds for session duration, connection counts, and bytes_out/bytes_in ratio.\n']
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
	EventID 12: Registry key and value create and delete operations map to this event type, which can be useful for monitoring for changes to Registry autostart locations, or specific malware registry modifications. Sysmon uses abbreviated versions of Registry root key names, with the following mappings: Key name  Abbreviation HKEY_LOCAL_MACHINE  HKLM; HKEY_USERS  HKU; HKEY_LOCAL_MACHINE\System\ControlSet00x   HKLM\System\CurrentControlSet; HKEY_LOCAL_MACHINE\Classes  HKCR



.Reported threat data:
	- Attack patterns: ['T1219']
	- Indicators of compromise: [{'filename': 'x86_64-unknown-linux-esxi.elf'}, {'filename': 'h3odp7l2u.exe'}, {'filename': 'hi9lezv.exe'}, {'filename': '072wiof7.exe'}, {'filename': 'k0d649u.exe'}, {'filename': '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat'}, {'filename': '2qfguc.exe'}, {'filename': '7hhel.exe'}, {'filename': '3ctjhm3.exe'}, {'filename': '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat'}, {'filename': 'bjiw49.exe'}, {'filename': '7l73h.exe'}, {'filename': '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat'}, {'filename': '0m6m882x2.exe'}, {'filename': 'inc.exe'}, {'filename': '61pd6n3t.exe'}, {'filename': 'mk1yd.exe'}, {'filename': 'a3mnw9.exe'}, {'filename': 'win.bin'}, {'filename': 'vw06lg0y.exe'}, {'filename': 'qgp2s6z.exe'}, {'filename': 'tt24n8xsl.exe'}]
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
	EventType: CreateKey or DeleteKey
Image: File path of the process that created or deleted a registry key
TargetObject: Complete path of the registry key
Every recommendation must be traceable to the provided context.
If a recommendation cannot be justified by the provided context, do not include it.

.Output format (plain text):
	One recommendation per line:
	[LABEL] <what to observe> | Source: <ATT&CK ID, CVE, or IoC key>
	If nothing in the context can be observed through this event type,
	output exactly: NO RECOMMENDATIONS
	
