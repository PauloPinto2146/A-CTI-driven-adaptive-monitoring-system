
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
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1190']
	- Remember to consider the reported indicators of compromise: ['6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141', 'x86_64-unknown-linux-esxi.elf', 'acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4', 'h3odp7l2u.exe', '31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502', 'hi9lezv.exe', '1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449', '072wiof7.exe', '1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11', 'k0d649u.exe', '24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7', '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat', '589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880', '2qfguc.exe', '5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241', '7hhel.exe', '60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6', '3ctjhm3.exe', '6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f', '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat', '765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a', 'bjiw49.exe', '7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245', '7l73h.exe', '8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4', '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat', '90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c', '0m6m882x2.exe', '97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2', 'inc.exe', 'bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc', '61pd6n3t.exe', 'd26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570', 'mk1yd.exe', 'd65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb', 'a3mnw9.exe', 'dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da', 'win.bin', 'ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22', 'vw06lg0y.exe', 'f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347', 'qgp2s6z.exe', 'ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b', 'tt24n8xsl.exe']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	