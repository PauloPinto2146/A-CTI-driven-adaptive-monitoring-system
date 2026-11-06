
.Context:
	EventID 11: File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops during initial infection.

	These are the applicable tags that you can use:
	Image: File path of the process that created the file
TargetFilename: Name of the file that was created
CreationUtcTime: File creation time

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
			<FileCreate onmatch="exclude">
				<Image condition="is">C:\Windows\System32\smss.exe</Image>				<!-- Microsoft:Windows: Session Manager SubSystem: Creates swapfile.sys,pagefile.sys,hiberfile.sys-->
				<Image condition="is">C:\Windows\system32\CompatTelRunner.exe</Image>				<!-- Microsoft:Windows: Windows 10 app, creates tons of cache files-->
				<Image condition="is">C:\Windows\system32\wbem\WMIADAP.EXE</Image>				<!-- Microsoft:Windows: WMI Performance updates-->
				<TargetFilename condition="begin with">C:\Windows\System32\DriverStore\Temp\</TargetFilename>				<!-- Microsoft:Windows: Temp files by DrvInst.exe-->
				<TargetFilename condition="begin with">C:\Windows\System32\wbem\Performance\</TargetFilename>				<!-- Microsoft:Windows: Created in wbem by WMIADAP.exe-->
				<TargetFilename condition="end with">WRITABLE.TST</TargetFilename>				<!-- Microsoft:Windows: Created in wbem by svchost-->
			</FileCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileCreate onmatch="exclude">
            <TargetFilename condition="contains">\AppData\Roaming\Microsoft\Windows\Recent\</TargetFilename>            <!--Microsoft:Windows:RecentFiles-->
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<FileCreate onmatch="exclude">
				<!--SECTION: Microsoft:Windows:Updates-->
				<TargetFilename condition="begin with">C:\$WINDOWS.~BT\Sources\SafeOS\SafeOS.Mount\</TargetFilename>				<!-- Microsoft:Windows: Feature updates containing lots of .exe and .sys-->
				<Image condition="begin with">C:\WINDOWS\winsxs\amd64_microsoft-windows</Image>				<!-- Microsoft:Windows: Windows update-->
			</FileCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<FileCreate onmatch="exclude">
				<!--SECTION: Microsoft:Windows-->
				<TargetFilename condition="begin with">C:\Windows\System32\Tasks\Microsoft\Windows\PLA\FabricTraces</TargetFilename>				<!-- Microsoft:Windows: -->
				<TargetFilename condition="begin with">C:\Windows\System32\Tasks\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask</TargetFilename>				<!-- Microsoft:Windows: -->
				<TargetFilename condition="begin with">C:\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerRoleUsageCollector</TargetFilename>				<!-- Microsoft:Windows: Customer Experience Improvement Program-->
				<TargetFilename condition="begin with">C:\Windows\System32\Tasks\Microsoft\Windows\Customer Experience Improvement Program\Server\ServerCeipAssistant</TargetFilename>				<!-- Microsoft:Windows: Customer Experience Improvement Program-->
			</FileCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup groupRelation="or">
			<FileCreate onmatch="exclude">
				<!-- Exclude Heartbeat -->
				<Rule groupRelation="and">
					<Image condition="is">C:\Windows\System32\svchost.exe</Image>
					<TargetFilename condition="is">C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive0.dat</TargetFilename>
				</Rule>
				<Rule groupRelation="and">
					<Image condition="is">C:\Windows\System32\svchost.exe</Image>
					<TargetFilename condition="is">C:\Windows\ServiceProfiles\LocalService\AppData\Local\lastalive1.dat</TargetFilename>
				</Rule>
			</FileCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<FileCreate onmatch="include">
				<Rule groupRelation="and" name="technique_id=T1203,technique_name=Exploitation for Client Execution">
					<Image condition="end with">\WINWORD.EXE</Image>
					<TargetFilename condition="contains any">.cab;.inf</TargetFilename>
				</Rule>
			</FileCreate>
		</RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">Desktop</TargetFilename>        <!--Files on the Desktop-->
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="technique_id=T1484.001,technique_name=Group Policy Modification" groupRelation="or">
			<FileCreate onmatch="include">
				<TargetFilename condition="begin with">C:\Windows\System32\GroupPolicy\Machine\Scripts</TargetFilename>
				<TargetFilename condition="begin with">C:\Windows\System32\GroupPolicy\User\Scripts</TargetFilename>
			</FileCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<FileCreate onmatch="include">
				<TargetFilename name="technique_id=T1059.001,technique_name=PowerShell" condition="end with">.ps1</TargetFilename>
				<TargetFilename name="technique_id=T1059.001,technique_name=PowerShell" condition="end with">.ps2</TargetFilename>				<!--PowerShell -->
			</FileCreate>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
     <EventFiltering>
          <RuleGroup name="technique_id=T1218.011,technique_name=Rundll32" groupRelation="or">
               <FileCreate onmatch="include">
                    <Image condition="image">rundll32.exe</Image>
               </FileCreate>
          </RuleGroup>
     </EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon FileCreate snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1567', 'T1219', 'T1083', 'T1566', 'T1486']
	- Remember to consider the reported indicators of compromise: ['x86_64-unknown-linux-esxi.elf', 'h3odp7l2u.exe', 'hi9lezv.exe', '072wiof7.exe', 'k0d649u.exe', '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat', '2qfguc.exe', '7hhel.exe', '3ctjhm3.exe', '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat', 'bjiw49.exe', '7l73h.exe', '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat', '0m6m882x2.exe', 'inc.exe', '61pd6n3t.exe', 'mk1yd.exe', 'a3mnw9.exe', 'win.bin', 'vw06lg0y.exe', 'qgp2s6z.exe', 'tt24n8xsl.exe']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	