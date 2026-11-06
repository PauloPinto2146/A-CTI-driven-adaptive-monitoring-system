
.Context:
	EventID 1: The process creation event provides extended information about a newly created process. The full command line provides context on the process execution. The ProcessGUID field is a unique value for this process across a domain to make event correlation easier. The hash is a full hash of the file with the algorithms in the HashType field.

	These are the applicable tags that you can use:
	Image: File path of the process being spawned/created. Considered also the child or source process
FileVersion: Protocol being used for the network connection
Description: Description of the image associated with the main process (child)
Product: Product name the image associated with the main process (child) belongs to
OriginalFileName: OriginalFileName from the PE header, added on compilation
Company: Company name the image associated with the main process (child) belongs to
CommandLine: Arguments which were passed to the executable associated with the main process
CurrentDirectory: The path without the name of the image associated with the process
IntegrityLevel: Integrity label assigned to a process
Hashes: Full hash of the file with the algorithms in the HashType field
ParentImage: File path that spawned/created the main process
ParentCommandLine: Arguments which were passed to the executable associated with the parent process

	ONLY use these conditions:
	Condition: Description
is: Default, values are equals
is any: The field is one of the ; delimited values
is not: Values are different
contains: The field contains this value
contains any: The field contains any of the ; delimited values
contains all: The field contains all of the ; delimited values
excludes: The field does not contain this value
excludes any: The field does not contain one or more of the ; delimited values
excludes all: The field does not contain any of the ; delimited values
begin with: The field begins with this value
end with: The field ends with this value
not begin with: The field does not begin with this value
not end with: The field does not end with this value
less than: Lexicographical comparison is less than zero
more than: Lexicographical comparison is more than zero
image: Match an image path (full path or only image name)
	Do NOT use any other variation like "end with any" or "image any". That will result in an invalid output.

.Examples
	Examples of rules that exclude benign noise:
	<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<ProcessCreate onmatch="exclude">
				<!--SECTION: Microsoft:Windows:svchost-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k appmodel -s StateRepository</CommandLine>
				<CommandLine condition="is">C:\WINDOWS\system32\svchost.exe -k appmodel -p -s tiledatamodelsvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k camera -s FrameServer</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k dcomlaunch -s LSM</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k dcomlaunch -s PlugPlay</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k defragsvc</CommandLine>				<!--Microsoft:Windows defragmentation-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k devicesflow -s DevicesFlowUserSvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k imgsvc</CommandLine>				<!--Microsoft:The Windows Image Acquisition Service-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s EventSystem</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s bthserv</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s nsi</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localService -s w32Time</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceAndNoImpersonation</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s Dhcp</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s EventLog</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s TimeBrokerSvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted -s WFDSConMgrSvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNetworkRestricted</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceAndNoImpersonation -s SensrSvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localServiceNoNetwork</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -p -s WPDBusEnum</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -p -s fhsvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s DeviceAssociationService</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s NcbService</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s SensorService</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s TabletInputService</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s UmRdpService</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s WPDBusEnum</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted -s WdiSystemHost</CommandLine>				<!--Microsoft:Windows: Diagnostic System Host-->
				<CommandLine condition="is">C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost</CommandLine>				<!--Microsoft:Windows: Diagnostic System Host-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted</CommandLine>				<!--Microsoft:Windows-->
				<CommandLine condition="is">C:\WINDOWS\system32\svchost.exe -k netsvcs -p -s wlidsvc</CommandLine>				<!--Microsoft:Windows: Windows Live Sign-In Assistant-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -p -s ncaSvc</CommandLine>				<!--Microsoft:Windows: Network Connectivity Assistant-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s BDESVC</CommandLine>				<!--Microsoft:Windows:Network: BitLocker Drive Encryption-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s BITS</CommandLine>				<!--Microsoft:Windows:Network: Background Intelligent File Transfer (BITS) -->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s CertPropSvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s DsmSvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s Gpsvc</CommandLine>				<!--Microsoft:Windows:Network: Group Policy -->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s ProfSvc</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s SENS</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s SessionEnv</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s Themes</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs -s Winmgmt</CommandLine>				<!--Microsoft:Windows: Windows Management Instrumentation (WMI) -->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -p -s DoSvc</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s Dnscache</CommandLine>				<!--Microsoft:Windows:Network: DNS caching, other uses -->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s LanmanWorkstation</CommandLine>				<!--Microsoft:Windows:Network: "Workstation" service, used for SMB file-sharing connections and RDP-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s NlaSvc</CommandLine>				<!--Microsoft:Windows:Network: Network Location Awareness-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService -s TermService</CommandLine>				<!--Microsoft:Windows:Network: Terminal Services (RDP)-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkService</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k networkServiceNetworkRestricted</CommandLine>				<!--Microsoft:Windows: Network services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k rPCSS</CommandLine>				<!--Microsoft:Windows Services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k secsvcs</CommandLine>
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k swprv</CommandLine>				<!--Microsoft:Software Shadow Copy Provider-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k unistackSvcGroup</CommandLine>				<!--Microsoft:Windows 10-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k utcsvc</CommandLine>				<!--Microsoft:Windows Services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wbioSvcGroup</CommandLine>				<!--Microsoft:Windows Services-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k werSvcGroup</CommandLine>				<!--Microsoft:Windows: ErrorReporting-->
				<CommandLine condition="is">C:\WINDOWS\System32\svchost.exe -k wsappx -p -s ClipSVC</CommandLine>				<!--Microsoft:Windows:Apps: Client License Service-->
				<CommandLine condition="is">C:\WINDOWS\system32\svchost.exe -k wsappx -p -s AppXSvc</CommandLine>				<!--Microsoft:Windows:Apps: AppX Deployment Service-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wsappx -s ClipSVC</CommandLine>				<!--Microsoft:Windows:Apps: Client License Service-->
				<CommandLine condition="is">C:\Windows\system32\svchost.exe -k wsappx</CommandLine>				<!--Microsoft:Windows:Apps-->
				<ParentCommandLine condition="is">C:\Windows\system32\svchost.exe -k netsvcs</ParentCommandLine>				<!--Microsoft:Windows: Network services: Spawns Consent.exe-->
				<ParentCommandLine condition="is">C:\Windows\system32\svchost.exe -k localSystemNetworkRestricted</ParentCommandLine>				<!--Microsoft:Windows-->
			</ProcessCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="begin with">C:\Program Files\Windows Defender\</Image>        <!--Microsoft:Windows:Defender in Win10-->
        <Image condition="is">C:\Windows\system32\MpSigStub.exe</Image>        <!--Microsoft:Windows: Microsoft Malware Protection Signature Update Stub-->
        <Image condition="begin with">C:\Windows\SoftwareDistribution\Download\Install\AM_</Image>        <!--Microsoft:Defender: Signature updates-->
        <Image condition="is">C:\Program Files\Microsoft Security Client\MpCmdRun.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<ProcessCreate onmatch="exclude">
				<!--SECTION: Generic Microsoft Windows Processes-->
				<CommandLine condition="begin with">C:\Windows\system32\DllHost.exe /Processid</CommandLine>				<!--Microsoft:Windows-->
				<CommandLine condition="is">C:\Windows\system32\SearchIndexer.exe /Embedding</CommandLine>				<!--Microsoft:Windows: Search Indexer-->
				<Image condition="end with">C:\Windows\System32\CompatTelRunner.exe</Image>				<!--Microsoft:Windows:Customer Experience Improvement-->
				<Image condition="is">C:\Windows\System32\MusNotification.exe</Image>				<!--Microsoft:Windows: Update popups-->
				<Image condition="is">C:\Windows\System32\MusNotificationUx.exe</Image>				<!--Microsoft:Windows: Update popups-->
				<Image condition="is">C:\Windows\System32\audiodg.exe</Image>				<!--Microsoft:Windows: Launched constantly-->
				<Image condition="is">C:\Windows\System32\conhost.exe</Image>				<!--Microsoft:Windows: Command line interface host process-->
				<Image condition="is">C:\Windows\System32\powercfg.exe</Image>				<!--Microsoft:Power configuration management-->
				<Image condition="is">C:\Windows\System32\wbem\WmiApSrv.exe</Image>				<!--Microsoft:Windows: WMI performance adpater host process-->
				<Image condition="is">C:\Windows\System32\wermgr.exe</Image>				<!--Microsoft:Windows:Windows error reporting/telemetry-->
				<Image condition="is">C:\Windows\SysWOW64\wermgr.exe</Image>				<!--Microsoft:Windows:Windows error reporting/telemetry-->
				<Image condition="is">C:\Windows\system32\sppsvc.exe</Image>				<!--Microsoft:Windows: Software Protection Service-->
				<IntegrityLevel condition="is">AppContainer</IntegrityLevel>				<!--Microsoft:Windows: Don't care about sandboxed processes-->
				<ParentCommandLine condition="begin with">%%SystemRoot%%\system32\csrss.exe ObjectDirectory=\Windows</ParentCommandLine>				<!--Microsoft:Windows:CommandShell: Triggered when programs use the command shell, but without attribution-->
				<ParentImage condition="is">C:\Windows\system32\SearchIndexer.exe</ParentImage>				<!--Microsoft:Windows:Search: Launches many uninteresting sub-processes-->
			</ProcessCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Rule name="technique_id=T1021.003,technique_name=Distributed Component Object Model" groupRelation="and">
          <ParentCommandLine condition="contains">-Embedding</ParentCommandLine>
          <ParentImage condition="is">c:\windows\system32\mmc.exe</ParentImage>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <CommandLine name="technique_id=T1027,technique_name=Obfuscated Files or Information" condition="contains">^</CommandLine>
        <CommandLine name="technique_id=T1027,technique_name=Obfuscated Files or Information" condition="contains">../../</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="technique_id=T1543.003,technique_name=Windows Service" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Rule groupRelation="and">
          <OriginalFileName condition="is">sc.exe</OriginalFileName>
          <CommandLine condition="contains">create</CommandLine>
        </Rule>
        <CommandLine condition="contains">New-Service</CommandLine>
        <Rule groupRelation="and">
          <OriginalFileName condition="is">wmic.exe</OriginalFileName>
          <CommandLine condition="contains all">service;call;create</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.40">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<ProcessCreate onmatch="include">
				<!-- COMMENT: T1059 Section - Command and Scripting Interpreter -->
				<Rule name="Windows Command Shell" groupRelation="or">
					<OriginalFileName name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="is">cmd.exe</OriginalFileName>
					<Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>
				</Rule>
				<Rule name="PowerShell" groupRelation="or">
					<OriginalFileName name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</OriginalFileName>
					<OriginalFileName name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell_ise.exe</OriginalFileName>
					<OriginalFileName name="technique_id=T1059.001,technique_name=PowerShell" condition="contains">Sqlps.exe</OriginalFileName>
					<CommandLine name="technique_id=T1059.001,technique_name=PowerShell" condition="contains">pester</CommandLine>
				</Rule>
			</ProcessCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.40">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <ProcessCreate onmatch="include">
                <CommandLine name="technique_id=T1027,technique_name=Obfuscated Files or Information" condition="contains">FromBase64</CommandLine>
            </ProcessCreate>
            <ProcessCreate onmatch="include">
                <CommandLine name="technique_id=T1027,technique_name=Obfuscated Files or Information" condition="contains">gzip</CommandLine>
            </ProcessCreate>
            <ProcessCreate onmatch="include">
                <CommandLine name="technique_id=T1027,technique_name=Obfuscated Files or Information" condition="contains">decompress</CommandLine>
            </ProcessCreate>
            <ProcessCreate onmatch="include">
                <CommandLine name="technique_id=T1027,technique_name=Obfuscated Files or Information" condition="contains">http</CommandLine>
            </ProcessCreate>
            <ProcessCreate onmatch="include">
                <CommandLine name="technique_id=T1027,technique_name=Obfuscated Files or Information" condition="contains">replace</CommandLine> <!--Kill Unicorns-->
            </ProcessCreate>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon ProcessCreate snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1003', 'T1489', 'T1190', 'T1219', 'T1021.002', 'T1112', 'T1566', 'T1078', 'T1486', 'T1027.002', 'T1018', 'T1021.001', 'T1569.002', 'T1490']
	- Remember to consider the reported indicators of compromise: ['6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141', 'x86_64-unknown-linux-esxi.elf', 'acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4', 'h3odp7l2u.exe', '31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502', 'hi9lezv.exe', '1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449', '072wiof7.exe', '1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11', 'k0d649u.exe', '24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7', '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat', '589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880', '2qfguc.exe', '5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241', '7hhel.exe', '60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6', '3ctjhm3.exe', '6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f', '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat', '765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a', 'bjiw49.exe', '7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245', '7l73h.exe', '8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4', '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat', '90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c', '0m6m882x2.exe', '97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2', 'inc.exe', 'bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc', '61pd6n3t.exe', 'd26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570', 'mk1yd.exe', 'd65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb', 'a3mnw9.exe', 'dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da', 'win.bin', 'ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22', 'vw06lg0y.exe', 'f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347', 'qgp2s6z.exe', 'ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b', 'tt24n8xsl.exe']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	