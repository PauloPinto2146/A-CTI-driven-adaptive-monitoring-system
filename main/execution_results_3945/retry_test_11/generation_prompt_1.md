
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
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1033', 'T1218.011', 'T1543.003', 'T1082', 'T1140', 'T1036', 'T1021', 'T1112', 'T1016', 'T1547.001', 'T1027', 'T1012', 'T1134', 'T1018']
	- Remember to consider the reported indicators of compromise: ['ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205', 'wiseman.EXE', 'fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c', 'wininet.dll']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	