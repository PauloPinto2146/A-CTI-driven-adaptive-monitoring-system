
.Context:
	EventID 2: The change file creation time event is registered when a file creation time is explicitly modified by a process. This event helps tracking the real creation time of a file. Attackers may change the file creation time of a backdoor to make it look like it was installed with the operating system. Note that many processes legitimately change the creation time of a file; it does not necessarily indicate malicious activity.

	These are the applicable tags that you can use:
	Image: File path of the process that changed the file creation time
TargetFilename: Full path name of the file
CreationUtcTime: New creation time of the file

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
      <FileCreateTime onmatch="exclude">
        <Image condition="image">OneDrive.exe</Image>        <!--OneDrive constantly changes file times-->
      </FileCreateTime>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="exclude">
        <Image condition="contains">setup</Image>        <!--Ignore setups-->
      </FileCreateTime>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.30"> <!-- Taken from SwiftOnSecurity rules-->
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<FileCreateTime onmatch="include">
				<TargetFilename name="technique_id=T1070.006,technique_name=Timestomp" condition="end with">.exe</TargetFilename> <!--Look for backdated executables anywhere-->
			</FileCreateTime>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="include">
        <Image name="technique_id=T1070.006,technique_name=Timestomp" condition="begin with">C:\Temp</Image>        <!--Look for timestomping in temp folders-->
        <Image name="technique_id=T1070.006,technique_name=Timestomp" condition="begin with">C:\Windows\Temp</Image>
        <Image name="technique_id=T1070.006,technique_name=Timestomp" condition="begin with">C:\Tmp</Image>
      </FileCreateTime>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="include">
        <Image name="technique_id=T1070.006,technique_name=Timestomp" condition="begin with">C:\Users</Image>        <!--Look for timestomping in user area-->
      </FileCreateTime>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30"> <!-- Taken from SwiftOnSecurity rules-->
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<FileCreateTime onmatch="include">
				<Image name="technique_id=T1070.006,technique_name=Timestomp" condition="begin with">\Device\HarddiskVolumeShadowCopy</Image> <!--Nothing should be written here-->
			</FileCreateTime>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon FileCreateTime snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1486']
	- Remember to consider the reported indicators of compromise: ['x86_64-unknown-linux-esxi.elf', 'h3odp7l2u.exe', 'hi9lezv.exe', '072wiof7.exe', 'k0d649u.exe', '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat', '2qfguc.exe', '7hhel.exe', '3ctjhm3.exe', '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat', 'bjiw49.exe', '7l73h.exe', '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat', '0m6m882x2.exe', 'inc.exe', '61pd6n3t.exe', 'mk1yd.exe', 'a3mnw9.exe', 'win.bin', 'vw06lg0y.exe', 'qgp2s6z.exe', 'tt24n8xsl.exe']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	