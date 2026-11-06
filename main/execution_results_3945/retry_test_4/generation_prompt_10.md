
.Context:
	EventID 10: The process accessed event reports when a process opens another process, an operation that’s often followed by information queries or reading and writing the address space of the target process. This enables detection of hacking tools that read the memory contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials for use in Pass-the-Hash attacks. Enabling it can generate significant amounts of logging if there are diagnostic utilities active that repeatedly open processes to query their state, so it generally should only be done so with filters that remove expected accesses.

	These are the applicable tags that you can use:
	SourceImage: File path of the source process that created a thread in another process
TargetImage: File path of the executable of the target process
GrantedAccess: The access flags (bitmask) associated with the process rights requested for the target process
CallTrace: Stack trace of where open process is called. Included is the DLL and the relative virtual address of the functions in the call stack right before the open process call

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
         <ProcessAccess onmatch="exclude">
            <SourceImage condition="is">C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe</SourceImage>
            <SourceImage condition="contains all">C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\DataCollection\;\OpenHandleCollector.exe</SourceImage>
         </ProcessAccess>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude">
        <SourceImage condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\StandaloneUpdater\OneDriveSetup.exe</SourceImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.60">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ProcessAccess onmatch="exclude">
            <SourceImage condition="is">C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</SourceImage>
         </ProcessAccess>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="exclude">
        <SourceImage condition="is">C:\Program Files\Microsoft Security Client\MsMpEng.exe</SourceImage>
        <SourceImage condition="is">C:\Program Files\Windows Defender\MsMpEng.exe</SourceImage>
        <SourceImage condition="contains all">C:\ProgramData\Microsoft\Windows Defender\Platform\;\MsMpEng.exe</SourceImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ProcessAccess onmatch="exclude">
            <SourceImage condition="is">C:\Program Files\WinZip\FAHWindow64.exe</SourceImage>
         </ProcessAccess>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- In some environments this causes HIGH CPU usage by sysmon, remove this module when that occurs -->
        <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=OS Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>          <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->
          <GrantedAccess>0x1FFFFF</GrantedAccess>          <!--Expect EDRs/AVs to also trigger this-->
        </Rule>
        <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=OS Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>          <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->
          <GrantedAccess>0x1F1FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=OS Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>          <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->
          <GrantedAccess>0x1010</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=OS Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage>          <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->
          <GrantedAccess>0x143A</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage name="technique_id=T1003,technique_name=OS Credential Dumping" condition="image">lsass.exe</TargetImage>
          <SourceImage name="technique_id=T1003,technique_name=OS Credential Dumping" condition="image">wsmprovhost.exe</SourceImage>
        </Rule>        
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <CallTrace name="technique_id=T1055.001,technique_name=Dynamic-link Library Injection" condition="contains all">C:\Windows\SYSTEM32\ntdll.dll;C:\Windows\System32\kernelbase.dll;UNKNOWN</CallTrace>          <!--@darkquassar-->
          <GrantedAccess name="technique_id=T1055.001,technique_name=Dynamic-link Library Injection" condition="contains any">0x1F0FFF;0x1F1FFF;0x143A;0x1410;0x1010;0x1F2FFF;0x1F3FFF;0x1FFFFF;0x147A;0x1028</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\PerfLogs\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\$Recycle.bin\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Intel\Logs\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Default\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Public\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\NetworkService\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Fonts\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Debug\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Media\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Help\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\addins\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\repair\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\security\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\system32\config\systemprofile\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="contains">VolumeShadowCopy</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="contains">\htdocs\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="contains">\wwwroot\</SourceImage>
        <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="contains">\Temp\</SourceImage>
        <Rule groupRelation="and">
          <SourceImage name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\</SourceImage>
          <SourceImage condition="not end with">\AppData\Local\Microsoft\Teams\current\Teams.exe</SourceImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <CallTrace name="technique_id=T1059.001,technique_name=PowerShell" condition="contains">System.Management.Automation.ni.dll</CallTrace>
          <SourceImage condition="is not">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</SourceImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <CallTrace name="technique_id=T1055,technique_name=Process Injection" condition="not begin with">C:\Windows\SYSTEM32\ntdll.dll</CallTrace>
          <CallTrace name="technique_id=T1055,technique_name=Process Injection" condition="not begin with">C:\Windows\SYSTEM32\win32u.dll</CallTrace>
          <CallTrace name="technique_id=T1055,technique_name=Process Injection" condition="not begin with">C:\Windows\SYSTEM32\wow64win.dll</CallTrace>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon ProcessAccess snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1056.001', 'T1140', 'T1134']
	- Remember to consider the reported indicators of compromise: ['wiseman.EXE', 'wininet.dll']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	