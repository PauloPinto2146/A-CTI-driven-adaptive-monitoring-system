
.Context:
	EventID 7: The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs to be configured with the "–l" option. It indicates the process in which the module is loaded, hashes and signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading. This event should be configured carefully, as monitoring all image load events will generate a significant amount of logging.

	These are the applicable tags that you can use:
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
      <ImageLoad onmatch="exclude">
          <Rule groupRelation="and">
            <!--    COMMENT: Removes unnecessary ImageLoaded events. These 4 DLLs flag as Process Injection normally --> 
            <!--    COMMENT: I consider this to be noise - there are many other notifications PowerShell has been started. -->
            <Image condition="is any">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe</Image>
            <OriginalFileName condition="is any">mscoree.dll;mscoreei.dll;mscoreeis.dll;clr.dll;clrjit.dll</OriginalFileName>
          </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="exclude">
        <Rule groupRelation="and">
          <Image condition="contains all"> C:\Users\;\AppData\Local\Microsoft\OneDrive;\FileCoAuth.exe</Image>
          <ImageLoaded condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\;\FileSyncTelemetryExtensions.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="contains all"> C:\Users\;\AppData\Local\Microsoft\OneDrive;\FileCoAuth.exe</Image>
          <ImageLoaded condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\;\FileCoAuthLib.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="contains all"> C:\Users\;\AppData\Local\Microsoft\OneDrive;\FileCoAuth.exe</Image>
          <ImageLoaded condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\;\OneDriveTelemetryStable.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="contains all"> C:\Users\;\AppData\Local\Microsoft\OneDrive;\FileCoAuth.exe</Image>
          <ImageLoaded condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\;\vcruntime140.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="contains all"> C:\Users\;\AppData\Local\Microsoft\OneDrive;\FileCoAuth.exe</Image>
          <ImageLoaded condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\;\UpdateRingSettings.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="contains all"> C:\Users\;\AppData\Local\Microsoft\OneDrive;\FileCoAuth.exe</Image>
          <ImageLoaded condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\;\LoggingPlatform.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="contains all"> C:\Users\;\AppData\Local\Microsoft\OneDrive;\FileCoAuth.exe</Image>
          <ImageLoaded condition="contains all">C:\Users\;\AppData\Local\Microsoft\OneDrive\;\FileCoAuth.exe</ImageLoaded>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<!--COMMENT:	Filtering these commonly loaded DLLs, which are so verbose they incur a lot of cost and have limited to no detection value-->
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="exclude">
        <Rule groupRelation="and">
          <Image condition="is">C:\Windows\System32\svchost.exe</Image>
          <ImageLoaded condition="is">C:\Windows\System32\netapi32.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Windows\System32\svchost.exe</Image>
          <ImageLoaded condition="is">C:\Windows\System32\msvcp110_win.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Windows\System32\svchost.exe</Image>
          <ImageLoaded condition="is">C:\Windows\System32\dsreg.dll</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="is">C:\Windows\System32\svchost.exe</Image>
          <ImageLoaded condition="is">C:\Windows\System32\perfctrs.dll</ImageLoaded>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<ImageLoad onmatch="include">
				<Rule groupRelation="and">
					<OriginalFileName name="technique_id=T1059.001,technique_name=PowerShell" condition="is">amsi.dll</OriginalFileName>
					<Image condition="excludes any">powershell.exe;powershell_ise.exe</Image>
				</Rule>
			</ImageLoad>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.40">
    <EventFiltering>
        <RuleGroup name="" groupRelation="or">
            <ImageLoad onmatch="include">
                <ImageLoaded name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="end with">mstask.dll</ImageLoaded>
            </ImageLoad>
        </RuleGroup>
    </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <OriginalFileName name="technique_id=T1003.004,technique_name=LSA Secrets" condition="is">comsvcs.dll</OriginalFileName>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<ImageLoad onmatch="include">
				<ImageLoaded name="technique_id=T1574.001,technique_name=DLL" condition="contains any">admin$;c$;\\;\appdata\;\temp\</ImageLoaded>				<!-- loaded from network file share -->
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">c:\programdata\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\Media\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\addins\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\system32\config\systemprofile\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\Debug\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\Temp</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\PerfLogs\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\Help\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Intel\Logs\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Temp</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\repair\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\security\</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">C:\Windows\Fonts\</ImageLoaded>
				<ImageLoaded condition="contains" name="technique_id=T1574.001,technique_name=DLL">Downloads</ImageLoaded>
				<ImageLoaded condition="contains" name="technique_id=T1574.001,technique_name=DLL">Public</ImageLoaded>
				<ImageLoaded condition="contains" name="technique_id=T1574.001,technique_name=DLL">Documents</ImageLoaded>
				<ImageLoaded condition="contains" name="technique_id=T1574.001,technique_name=DLL">Music</ImageLoaded>
				<ImageLoaded condition="contains" name="technique_id=T1574.001,technique_name=DLL">Video</ImageLoaded>
				<ImageLoaded condition="begin with" name="technique_id=T1574.001,technique_name=DLL">file:</ImageLoaded>
				<ImageLoaded name="technique_id=T1574.001,technique_name=DLL" condition="contains">$Recycle.bin\</ImageLoaded>
				<ImageLoaded name="technique_id=T1574.001,technique_name=DLL" condition="contains">\Windows\IME\</ImageLoaded>
			</ImageLoad>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="end with">wmiutils.dll</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon ImageLoad snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1218.011', 'T1059.003']
	- Remember to consider the reported indicators of compromise: ['ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205', 'wiseman.EXE', 'fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c', 'wininet.dll']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	