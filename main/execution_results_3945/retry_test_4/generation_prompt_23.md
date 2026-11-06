
.Context:
	EventID 23: A file was deleted. Additionally to logging the event, the deleted file is also saved in the ArchiveDirectory (which is C:\Sysmon by default). Under normal operating conditions this directory might grow to an unreasonable size - see event ID 26: FileDeleteDetected for similar behavior but without saving the deleted files.

	These are the applicable tags that you can use:
	Image: File path of the process that deleted the file
TargetFilename: The path of the deleted file
Hashes: The hashes of the file, types set in the config. This also determines the stored filename
IsExecutable: Boolean statement whether the file is a PE file
Archived: Boolean statement whether the file was stored in the configured archive folder

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
<Sysmon schemaversion="4.40">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileDelete onmatch="exclude">
            <User condition="contains any">NETWORK SERVICE; LOCAL SERVICE</User>
            <Rule name="PowerShell Profile Deletion" groupRelation="and">
               <TargetFilename condition="contains">AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive</TargetFilename>
               <Image condition="is">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Image>
             </Rule>
         </FileDelete>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.40">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileDelete onmatch="include">
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\Downloads\</TargetFilename>               <!--User Download folder-->
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\Appdata\Local\Temp\</TargetFilename>               <!--User Temp folder-->
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\Appdata\Local\Microsoft\Windows\INetCache\Content.Outlook\</TargetFilename>               <!--Microsoft Outlook Temp folder-->
            <Image condition="Contains">Downloads</Image>
            <Image condition="contains">Temp</Image>
            <Image condition="contains">AppData</Image>
            <Image condition="contains">ProgramData</Image>
            <Image condition="contains">Public</Image>
            <TargetFilename condition="contains">INetCache/Content.Outlook</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\Downloads\</TargetFilename> <!--User Download folder-->
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\Appdata\</TargetFilename> <!--User Temp folder-->
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="contains">\Appdata\Local\Microsoft\Windows\INetCache\Content.Outlook\</TargetFilename> <!--Microsoft Outlook Temp folder-->
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
         </FileDelete>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.40">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileDelete onmatch="include">
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\Temp</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\System32</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\SysWOW64</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">AppData</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Intel</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Mozilla</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\chocolatey\logs</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\DeviceSync</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\PlayReady</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\User Account Pictures</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Crypto\DSS\MachineKeys</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\NetFramework\BreadcrumbStore</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Office\Heartbeat</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Windows\WER\ReportQueue</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Windows\WER\Temp</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Windows\WER\Temp</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Windows\WER\Temp</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Windows\WER\Temp</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\ProgramData\Microsoft\Windows\WER\Temp</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Intel</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Mozilla</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\chocolatey\logs</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\DeviceSync</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\PlayReady</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\User Account Pictures</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\Crypto\DSS\MachineKeys</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\Crypto\RSA\MachineKeys</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\NetFramework\BreadcrumbStore</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\Office\Heartbeat</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\Windows\WER\ReportArchive</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\Windows\WER\ReportQueue</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Users\All Users\Microsoft\Windows\WER\Temp</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\Tasks</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\tracing</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\Registration\CRMLog</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\System32\Tasks</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\System32\spool\drivers\color</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
            <Rule groupRelation="and">
               <TargetFilename condition="begin with">C:\Windows\SysWOW64\Tasks</TargetFilename>
               <TargetFilename condition="contains any">.com;.bat;.exe;.reg;.ps1;.vbs;.vba;.lnk;.doc;.xls;.hta;.bin;.7z;.dll;.xla;.cmd;.sh;.lnk;.pptm;.scr;.msi;.sct</TargetFilename>
            </Rule>
         </FileDelete>
      </RuleGroup>
   </EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon FileDelete snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1070.004']
	- Remember to consider the reported indicators of compromise: ['ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205', 'wiseman.EXE', 'fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c', 'wininet.dll']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	