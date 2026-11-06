
.Context:
	EventID 13: This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD.

	These are the applicable tags that you can use:
	EventType: SetValue
Image: File path of the process that that modified a registry value
TargetObject: Complete path of the modified registry key
Details: Details added to the registry key

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
			<RegistryEvent onmatch="exclude">
				<Image condition="is">System</Image>
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<RegistryEvent onmatch="exclude">
				<!--Windows:Bootup Control-->
				<TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit</TargetObject>				<!--Microsoft:Windows:lsass.exe: Boot noise-->				<!--Win8+-->
				<TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit\AuditPolicy</TargetObject>				<!--Microsoft:Windows:lsass.exe: Boot noise-->				<!--Win8+-->
				<TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Audit\PerUserAuditing\System</TargetObject>				<!--Microsoft:Windows:lsass.exe: Boot noise-->				<!--Win8+-->
				<TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\SspiCache</TargetObject>				<!--Microsoft:Windows:lsass.exe: Boot noise-->				<!--Win8+-->
				<TargetObject condition="end with">HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains</TargetObject>				<!--Microsoft:Windows:lsass.exe: Boot noise-->				<!--Win8+-->
				<TargetObject condition="end with">HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit</TargetObject>				<!--Microsoft:Windows:lsass.exe: Boot noise-->				<!--Win8+-->
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<RegistryEvent onmatch="exclude">
				<TargetObject condition="contains">\OpenWithProgids</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "FileExts"-->
				<TargetObject condition="end with">\OpenWithList</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "FileExts"-->
				<TargetObject condition="end with">\UserChoice</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "FileExts"-->
				<TargetObject condition="end with">\UserChoice\ProgId</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "FileExts"-->				<!--Win8+-->
				<TargetObject condition="end with">\UserChoice\Hash</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "FileExts"-->				<!--Win8+-->
				<TargetObject condition="end with">\OpenWithList\MRUList</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "FileExts"-->
				<TargetObject condition="end with">} 0xFFFF</TargetObject>				<!--Microsoft:Windows: Remove noise from explorer.exe from monitoring ShellCached binary keys-->				<!--Win8+-->
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<RegistryEvent onmatch="exclude">
				<Image condition="end with">Office\root\integration\integrator.exe</Image>				<!--Microsoft:Office: C2R client-->
				<Image condition="image">C:\WINDOWS\system32\backgroundTaskHost.exe</Image>				<!--Microsoft:Windows: Changes association registry keys-->
				<Image condition="is">C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe</Image>				<!--Microsoft:Office: C2R client-->
				<Image condition="is">C:\Program Files\Windows Defender\MsMpEng.exe</Image>				<!--Microsoft:Windows:Defender-->
				<Image condition="is">C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe</Image>				<!--Microsoft:Cortana-->
				<Image condition="is">C:\Program Files\Microsoft Application Virtualization\Client\AppVClient.exe</Image>
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<RegistryEvent onmatch="exclude">
				<!--Sevices autostart-->
				<TargetObject condition="end with">\services\clr_optimization_v2.0.50727_32\Start</TargetObject>				<!--Microsoft:dotNet: Windows 7-->
				<TargetObject condition="end with">\services\clr_optimization_v2.0.50727_64\Start</TargetObject>				<!--Microsoft:dotNet: Windows 7-->
				<TargetObject condition="end with">\services\clr_optimization_v4.0.30319_32\Start</TargetObject>				<!--Microsoft:dotNet: Windows 10-->
				<TargetObject condition="end with">\services\clr_optimization_v4.0.30319_64\Start</TargetObject>				<!--Microsoft:dotNet: Windows 10-->
				<TargetObject condition="end with">\services\DeviceAssociationService\Start</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "\Start"-->
				<TargetObject condition="end with">\services\BITS\Start</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "\Start"-->
				<TargetObject condition="end with">\services\TrustedInstaller\Start</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "\Start"-->
				<TargetObject condition="end with">\services\tunnel\Start</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "\Start"-->
				<TargetObject condition="end with">\services\UsoSvc\Start</TargetObject>				<!--Microsoft:Windows: Remove noise from monitoring "\Start"-->
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject name="technique_id=T1546.007,technique_name=Netsh Helper DLL" condition="contains">SOFTWARE\Microsoft\Netsh</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject name="technique_id=T1543,technique_name=Service Creation" condition="begin with">HKLM\SYSTEM\CurrentControlSet\Services</TargetObject>
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<RegistryEvent onmatch="include">
				<!--Windows Defender tampering | Credit @ion-storm -->
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Microsoft\Security Center\AntiVirusDisableNotify</TargetObject>
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware</TargetObject>
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus</TargetObject>
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring</TargetObject>
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection</TargetObject>
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable</TargetObject>
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\SpyNetReporting</TargetObject>
				<TargetObject name="technique_id=T1089,technique_name=Disabling Security Tools" condition="begin with">HKLM\SOFTWARE\Policies\Microsoft\Windows Defender</TargetObject>				<!--Microsoft:Defender: Detect changes to Defender administrative settings to monitor for disablement-->
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<RegistryEvent onmatch="include">
				<!--Networking-->
				<TargetObject condition="begin with">HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order</TargetObject>				<!--Microsoft:Windows: Order of network providers that are checked to connect to destination -->
				<TargetObject condition="begin with">HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles</TargetObject>
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<RegistryEvent onmatch="include">
				<!--Windows shell hijack-->
				<TargetObject condition="contains">\Classes\AllFilesystemObjects</TargetObject>				<!--Microsoft:Windows:Explorer:-->
				<TargetObject condition="contains">\Classes\Directory</TargetObject>				<!--Microsoft:Windows:Explorer-->
				<TargetObject condition="contains">\Classes\Drive</TargetObject>				<!--Microsoft:Windows:Explorer-->
				<TargetObject condition="contains">\Classes\Folder</TargetObject>				<!--Microsoft:Windows:Explorer: ContextMenuHandlers, DragDropHandlers, CopyHookHandlers-->
				<TargetObject condition="contains">\ContextMenuHandlers</TargetObject>
				<TargetObject condition="contains">\CurrentVersion\Shell</TargetObject>				<!--Microsoft:Windows: Shell Folders, ShellExecuteHooks, ShellIconOverloadIdentifers, ShellServiceObjects-->
				<TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks</TargetObject>				<!--Microsoft:Windows: ShellExecuteHooks-->
				<TargetObject condition="begin with">HKLM\Software\Microsoft\Windows\CurrentVersion\explorer\ShellServiceObjectDelayLoad</TargetObject>				<!--Microsoft:Windows: ShellExecuteHooks-->
			</RegistryEvent>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon RegistryEvent snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1056.001', 'T1543.003', 'T1082', 'T1112', 'T1547.001', 'T1012']
	- Remember to consider the reported indicators of compromise: ['wiseman.EXE', 'wininet.dll']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	