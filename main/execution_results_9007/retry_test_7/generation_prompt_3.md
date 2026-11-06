
.Context:
	EventID 3: The network connection event logs TCP/UDP connections on the machine. It is disabled by default. Each connection is linked to a process through the ProcessId and ProcessGuid fields. The event also contains the source and destination host names IP addresses, port numbers and IPv6 status.

	These are the applicable tags that you can use:
	Image: File path of the process that made the network connection
Protocol: Protocol being used for the network connection
Initiated: Indicates whether the process initiated the TCP connection
SourceIsIpv6: Is the source IP an Ipv6 address
SourceIp: Source IP address that made the network connection
SourceHostname: DNS name of the host that made the network connection
SourcePort: Source port number
SourcePortName: Name of the source port being used
DestinationIsIpv6: Is the destination IP an Ipv6 address
DestinationIp: IP address destination
DestinationHostname: DNS name of the host that is contacted
DestinationPort: Destination port number
DestinationPortName: Name of the destination port

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
    <RuleGroup name="Exclude_UDP" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<NetworkConnect onmatch="exclude">
				<!--SECTION: Microsoft-->
				<DestinationHostname condition="end with">.windowsupdate.microsoft.com</DestinationHostname>				<!--Microsoft:Update delivery-->
				<DestinationHostname condition="end with">.windowsupdate.com</DestinationHostname>				<!--Microsoft:Update delivery-->
				<DestinationHostname condition="end with">wustat.windows.com</DestinationHostname>				<!--Microsoft:Update delivery-->
				<DestinationHostname condition="end with">go.microsoft.com</DestinationHostname>				<!--Microsoft:Update delivery-->
				<DestinationHostname condition="end with">.update.microsoft.com</DestinationHostname>				<!--Microsoft:Update delivery-->
				<DestinationHostname condition="end with">download.microsoft.com</DestinationHostname>				<!--Microsoft:Update delivery-->
				<DestinationHostname condition="end with">microsoft.com.akadns.net</DestinationHostname>				<!--Microsoft:Update delivery-->
				<DestinationHostname condition="end with">microsoft.com.nsatc.net</DestinationHostname>				<!--Microsoft:Update delivery-->
			</NetworkConnect>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	<example>
<Sysmon schemaversion="4.40">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Native Windows tools - Living off the land -->
        <!-- Research needed on how many of these tools are capable of making a network connection - see ipconfig.exe -->
        <Rule name="Unusual Connection" groupRelation="or">
          <Image condition="image">dllhost.exe</Image>
          <Image condition="image">hh.exe</Image>          <!--Microsoft:Windows: HTML Helper-->
          <Image condition="image">klist.exe</Image>          <!--Microsoft:Windows: show cached kerberos tickets -->
          <Image condition="image">schtasks.exe</Image>          <!--Microsoft:Windows: Command and Scripting Interpreter to local and remote tasks -->
          <Image condition="image">taskkill.exe</Image>          <!--Microsoft:Windows: Kill processes, has remote ability -->
          <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
          <Image name="technique_id=T1218.010,technique_name=Regsvr32" condition="image">regsvr32.exe</Image>          <!--Mitre T1218.010-->          <!--Mitre T1218.011-->
          <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>          <!--Mitre T1016-->          <!--Mitre T1546.007-->          <!--Mitre T1518.001-->          <!--Microsoft:Windows: manipulate the firewall -->
          <Image name="technique_id=T1548.002,technique_name=Bypass User Account Control" condition="image">xwizard.exe</Image>
          <Image name="technique_id=T1564.004,technique_name=NTFS File Attributes" condition="image">esentutl.exe</Image>
          <Image name="technique_id=T1112,technique_name=Modify Registry" condition="image">reg.exe</Image>          <!--Mitre T1552.002-->          <!--Mitre T1012-->          <!--Mitre T1112-->          <!--Microsoft:Windows: reads and modifies the Windows register -->
          <Image name="technique_id=T1134,technique_name=Access Token Manipulation" condition="image">runas.exe</Image>          <!--Microsoft:Windows: run a process as another user -->
          <Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">net1.exe</Image>          <!--Mitre T1018-->          <!--Mitre T1021.002-->          <!--Mitre T1087-->          <!--Mitre T1135-->          <!--Mitre T1069-->          <!--Mitre T1016-->          <!--Microsoft:Windows: Launched by "net.exe", but it may not detect connections either -->
          <Image name="technique_id=T1070,technique_name=Indicator Removal" condition="image">wevtutil.exe</Image>          <!--Microsoft:Windows: read and modify the Windows Eventlog -->
        </Rule>
        <Image name="technique_id=T1003,technique_name=OS Credential Dumping" condition="image">RpcPing.exe</Image>
        <Rule name="Discovery" groupRelation="or">
          <Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">ipconfig.exe</Image>          <!--Microsoft:Windows: shows ip configuration -->
          <Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">nbtstat.exe</Image>          <!--Microsoft:Windows: NetBIOS statistics, attackers use to enumerate local network -->
          <Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">nslookup.exe</Image>          <!--Microsoft:Windows: shows DNS configuration and enables quering -->
          <Image name="technique_id=T1018,technique_name=Remote System Discovery" condition="image">net.exe</Image>          <!--Mitre T1201-->          <!--Mitre T1007-->          <!--Mitre T1124-->          <!--Mitre T1018-->          <!--Mitre T1049-->          <!--Mitre T1087-->          <!--Mitre T1135-->          <!--Mitre T1069-->          <!--Mitre T1016-->          <!--Mitre T1021.002-->          <!--Microsoft:Windows: "net use"/"net view" used by attackers to surveil and connect with file shares from command line-->
          <Image name="technique_id=T1018,technique_name=Remote System Discovery" condition="image">nslookup.exe</Image>          <!--Microsoft:Windows: Retrieve data over DNS -->
          <Image name="technique_id=T1033,technique_name=System Owner/User Discovery" condition="image">nltest.exe</Image>          <!-- netlogon testing utility-->
          <Image name="technique_id=T1033,technique_name=System Owner/User Discovery" condition="image">quser.exe</Image>          <!--Microsoft:Windows: shows logged-on users -->
          <Image name="technique_id=T1049,technique_name=System Network Connections Discovery" condition="image">netstat.exe</Image>          <!--Mitre T1016-->          <!--Mitre T1049-->          <!--Microsoft:Windows: shows protocol statistics and current TCP/IP network connections -->
          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qprocess.exe</Image>          <!--Microsoft:Windows: shows information about processes -->
          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">query.exe</Image>          <!--Microsoft:Windows: shows information about processes -->
          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qwinsta.exe</Image>          <!--Microsoft:Windows: Remotely query login sessions on a server or workstation-->
          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">rwinsta.exe</Image>          <!--Microsoft:Windows: Disconnect remote sessions-->
          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">tasklist.exe</Image>          <!--Mitre T1057-->          <!--Mitre T1007-->          <!--Microsoft:Windows: shows current running processes-->
        </Rule>
        <Rule name="Ingress Tool Transfer" groupRelation="or">
          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">expand.exe</Image>
          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">extrac32.exe</Image>
          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">IEExec.exe</Image>
          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">Print.Exe</Image>
        </Rule>
        <Rule name="Execution" groupRelation="or">
          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">cscript.exe</Image>
          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">desktopimgdownldr.exe</Image>
          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">pcalua.exe</Image>          <!--Microsoft:Windows: Program Compatibility Assistant)-->
          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">winrs.exe</Image>
          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">wscript.exe</Image>
          <Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">Msdt.exe</Image>
          <Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">msiexec.exe</Image>
          <Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">RegisterCimProvider.exe</Image>
          <Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">ScriptRunner.exe</Image>
          <Image name="technique_id=T1127,technique_name=Trusted Developer Utilities Proxy Execution" condition="image">dfsvc.exe</Image>
        </Rule>
        <Rule name="Services" groupRelation="or">
          <Image name="technique_id=T1569.002,technique_name=Service Execution" condition="image">dnscmd.exe</Image>
          <Image name="technique_id=T1543.003,technique_name=Windows Service" condition="image">sc.exe</Image>
          <Image name="technique_id=T1053,technique_name=Scheduled Task/Job" condition="image">taskeng.exe</Image>          <!--Microsoft:Windows: taskscheduler -->
        </Rule>
        <Rule name="Shells and Terminals" groupRelation="or">
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">OpenConsole.exe</Image>          <!--Microsoft Windows Terminal-->
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>          <!--Microsoft:Windows: PowerShell interface-->
          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">WindowsTerminal.exe</Image>          <!--Microsoft Windows Terminal-->
          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>          <!--Microsoft:Windows: Command prompt-->
          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">bash.exe</Image>          <!--Microsoft:Windows: bash on Windows, Linux subsystem-->
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<NetworkConnect onmatch="include">
				<!--Native Windows tools - Living off the land-->
				<Image name="technique_id=T1053,technique_name=Scheduled Task/Job" condition="image">at.exe</Image>				<!--Microsoft:Windows: Remote task scheduling -->
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">certutil.exe</Image>				<!--Microsoft:Windows: Certificate tool can contact outbound-->
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">cscript.exe</Image>
				<Image condition="image">java.exe</Image>				<!--Java: Monitor usage of vulnerable application-->
				<Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">msiexec.exe</Image>
				<Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">net.exe</Image>				<!--Mitre T1018-->				<!--Mitre T1021.002-->				<!--Mitre T1087-->				<!--Mitre T1135-->				<!--Mitre T1069-->				<!--Mitre T1016-->				<!--Microsoft:Windows: "net use"/"net view" used by attackers to surveil and connect with file shares from command line-->
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">notepad.exe</Image>
				<Image name="technique_id=T1012,technique_name=Query Registry" condition="image">reg.exe</Image>				<!--Mitre T1012-->				<!--Mitre T1112-->				<!--Microsoft:Windows: Remote Registry-->
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">regsvr32.exe</Image>
				<Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>
				<Image name="technique_id=T1543.003,technique_name=Windows Service" condition="image">sc.exe</Image>				<!--Microsoft:Windows: Remotely change Windows service settings from command line-->
				<Image name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="image">wmic.exe</Image>				<!--T1047-->				<!--Mitre T1135-->				<!--Microsoft:WindowsManagementInstrumentation-->
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">wscript.exe</Image>				<!--Microsoft:WindowsScriptingHost-->
				<Image condition="image">driverquery.exe</Image>				<!--Microsoft:Windows: Remote recognisance of system configuration, oudated/vulnerable drivers -->
				<Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">dsquery.exe</Image>				<!--Microsoft: Query Active Directory -->
				<Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">AdFind.exe</Image>
				<Image condition="image">hh.exe</Image>				<!--Microsoft:Windows: HTML Help Executable, opens CHM files -->
				<Image condition="image">infDefaultInstall.exe</Image>
				<Image condition="image">javaw.exe</Image>				<!--Java: Monitor usage of vulnerable application and init from JAR files -->
				<Image condition="image">javaws.exe</Image>				<!--Java: Monitor usage of vulnerable application and init from JAR files -->
				<Image name="technique_id=T1543.003,technique_name=Windows Service" condition="image">mmc.exe</Image>				<!--Microsoft:Windows: -->
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">msbuild.exe</Image>
				<Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">nbtstat.exe</Image>				<!--Microsoft:Windows: NetBIOS statistics, attackers use to enumerate local network -->
				<Image name="technique_id=T1018,technique_name=Remote System Discovery" condition="image">nslookup.exe</Image>				<!--Microsoft:Windows: Retrieve data over DNS -->
				<Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qprocess.exe</Image>
				<Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qwinsta.exe</Image>				<!--Microsoft:Windows: Remotely query login sessions on a server or workstation-->
				<Image name="technique_id=T1218.009,technique_name=Regsvcs/Regasm" condition="image">regsvcs.exe</Image>
				<Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">rwinsta.exe</Image>				<!--Microsoft:Windows: Disconnect remote sessions -->
				<Image name="technique_id=T1053,technique_name=Scheduled Task/Job" condition="image">schtasks.exe</Image>				<!--Microsoft:Windows: Command and Scripting Interpreter to local and remote tasks -->
				<Image name="technique_id=T1685,technique_name=Disable or Modify Tools" condition="image">taskkill.exe</Image>				<!--Microsoft:Windows: Kill processes, has remote ability -->
				<Image name="technique_id=T1218,technique_name=System Binary Proxy Execution" condition="image">replace.exe</Image>
			</NetworkConnect>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <RuleGroup name="Outbound SMB anomalous connections" groupRelation="or">  <!--May need tuning on servers-->
      <NetworkConnect onmatch="include">
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
          <ProcessId condition="is not">4</ProcessId>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<NetworkConnect onmatch="include">
				<!--Eventhough DNS is a commmon exfil channel, you should monitor that via some other way, Sysmon is not ideal for that-->
				<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">22</DestinationPort>				<!--SSH protocol-->
				<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">23</DestinationPort>				<!--Telnet protocol-->
				<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">25</DestinationPort>				<!--SMTP mail protocol-->
				<Rule groupRelation="and">
					<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">88</DestinationPort>				<!--Kerberos protocol-->
					<Image condition="is not">C:\Windows\System32\lsass.exe</Image>															<!--exclude LSASS for Kerberos protocol-->
        		</Rule>
				<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">3389</DestinationPort>				<!--Microsoft:Windows:RDP-->
				<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5800</DestinationPort>				<!--VNC protocol-->
				<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5900</DestinationPort>				<!--VNC protocol-->
				<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5985</DestinationPort>				<!--WinRM protocol-->
				<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5986</DestinationPort>				<!--WinRM protocol-->
				<DestinationPort name="technique_id=T1087.002,technique_name=Account Discovery: Domain Account" condition="is">9389</DestinationPort>				<!--ADWS port-->
			</NetworkConnect>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users</Image>        <!--Tools downloaded by users can use other processes for networking, but this is a very valuable indicator.-->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\ProgramData</Image>        <!--Normally, network communications should be sourced from "Program Files" not from ProgramData, something to look at-->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Temp</Image>        <!--Suspicious anything would communicate from the system-level temp directory-->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Temp</Image>        <!--Suspicious anything would communicate from the temp directory-->
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\PerfLogs\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\$Recycle.bin\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Intel\Logs\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Default\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\Public\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Users\NetworkService\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Fonts\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Debug\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Media\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\Help\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\addins\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\repair\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\security\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\Windows\system32\config\systemprofile\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\htdocs\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\wwwroot\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Local\Temp\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\Roaming\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\AppData\LocalLow\</Image>
        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">C:\Windows\SysWOW64</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
</example>

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon NetworkConnect snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1557', 'T1071', 'T1190', 'T1567', 'T1219', 'T1021.002', 'T1018', 'T1021.001', 'T1569.002']
	- Remember to consider the reported indicators of compromise: ['6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141', 'x86_64-unknown-linux-esxi.elf', 'acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4', 'h3odp7l2u.exe', '31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502', 'hi9lezv.exe', '1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449', '072wiof7.exe', '1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11', 'k0d649u.exe', '24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7', '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat', '589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880', '2qfguc.exe', '5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241', '7hhel.exe', '60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6', '3ctjhm3.exe', '6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f', '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat', '765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a', 'bjiw49.exe', '7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245', '7l73h.exe', '8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4', '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat', '90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c', '0m6m882x2.exe', '97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2', 'inc.exe', 'bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc', '61pd6n3t.exe', 'd26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570', 'mk1yd.exe', 'd65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb', 'a3mnw9.exe', 'dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da', 'win.bin', 'ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22', 'vw06lg0y.exe', 'f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347', 'qgp2s6z.exe', 'ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b', 'tt24n8xsl.exe', 'incblog.su', 'incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion', 'incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	