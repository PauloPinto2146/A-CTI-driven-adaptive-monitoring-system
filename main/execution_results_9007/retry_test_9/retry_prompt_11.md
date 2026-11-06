
.The following Sysmon configuration was REJECTED by Sysmon:
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup groupRelation="or">
      <!-- IOC file names -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">x86_64-unknown-linux-esxi.elf;h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;win.bin;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</TargetFilename>
      </FileCreate>

      <!-- Files dropped to temporary or download directories (T1567) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">\Temp\;\\Downloads\</TargetFilename>
      </FileCreate>

      <!-- Files placed in Startup autostart locations (T1219) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">\Microsoft\Windows\Start Menu\Programs\Startup\</TargetFilename>
      </FileCreate>

      <!-- Uncommon ransomware extensions (T1486) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="ends with any">.locked;.crypted;.enc</TargetFilename>
      </FileCreate>

      <!-- Executable or script files created as a result of phishing attachment execution (T1566) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="ends with any">.exe;.js;.vbs</TargetFilename>
      </FileCreate>

      <!-- Files created by directory enumeration tools (T1083) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">dir;tree;ls</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>


.Recall the valid Sysmon tags:
	Image: File path of the process that created the file
TargetFilename: Name of the file that was created
CreationUtcTime: File creation time

.Recall the valid Sysmon conditions:
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

.Task:
	Fix the configuration so that Sysmon accepts it.


.Rules:
	- Keep the structure exactly as in the examples: a <RuleGroup name="" groupRelation="or"> containing the event element (e.g. <ProcessCreate onmatch="include">) and then the rules
	- Preserve every rule and every IOC value. Do not delete, add or merge rules
	- If a condition is invalid, replace it with the closest valid one that keeps the same meaning
	- Only use the valid tags and conditions mentioned earlier
	- Escape special characters in values (&amp; &lt; &gt;)
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

Output ONLY the corrected XML. No markdown fences, no explanations.
