
## Test case A

### Sysmon Instruction A

```
Context:

EventID 3 Network connection
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

Condition 	Description
is 	Default, values are equals
is any 	The field is one of the ; delimited values
is not 	Values are different
contains 	The field contains this value
contains any 	The field contains any of the ; delimited values
contains all 	The field contains all of the ; delimited values
excludes 	The field does not contain this value
excludes any 	The field does not contain one or more of the ; delimited values
excludes all 	The field does not contain any of the ; delimited values
begin with 	The field begins with this value
end with 	The field ends with this value
not begin with 	The field does not begin with this value
not end with 	The field does not end with this value
less than 	Lexicographical comparison is less than zero
more than 	Lexicographical comparison is more than zero
image 	Match an image path (full path or only image name). For example: lsass.exe will match c:\windows\system32\lsass.exe


Use these examples of NetworkConnect for your final result:
['<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="exclude">\r\n        <Image condition="end with">AppData\\Roaming\\Dropbox\\bin\\Dropbox.exe</Image>        <!--Dropbox-->\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>', '<Sysmon schemaversion="4.40">\n  <EventFiltering>\n    <RuleGroup name="" groupRelation="or">\n      <NetworkConnect onmatch="exclude">\n        <Image condition="end with">winlogbeat.exe</Image> <!--Credit d4ph1l -->\n        <Image condition="end with">packetbeat.exe</Image>\n      </NetworkConnect>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>\n', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="exclude">\r\n        <Image condition="is">C:\\Program Files\\ESET\\ESET Nod32 Antivirus\\ekrn.exe</Image>        <!--Credit d4ph1l -->\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="exclude">\r\n        <Rule groupRelation="and">\r\n          <Image condition="is">C:\\Windows\\System32\\lsass.exe</Image>\r\n          <DestinationPort condition="is">88</DestinationPort>          <!--Kerberos protocol-->\r\n        </Rule>\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="exclude">\r\n\t\t\t\t<Image condition="image">OneDrive.exe</Image>\t\t\t\t<!--Microsoft:OneDrive-->\r\n\t\t\t\t<Image condition="image">OneDriveStandaloneUpdater.exe</Image>\t\t\t\t<!--Microsoft:OneDrive-->\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>', '<Sysmon schemaversion="4.30">\n    <EventFiltering>\n        <RuleGroup name="" groupRelation="or">\n            <NetworkConnect onmatch="exclude">\n                <Image condition="end with">ownCloud\\owncloud.exe</Image>                <!--Owncloud-->\n            </NetworkConnect>\n        </RuleGroup>\n    </EventFiltering>\n</Sysmon>', '<Sysmon schemaversion="4.30">\n  <EventFiltering>\n    <RuleGroup name="" groupRelation="or">\n      <NetworkConnect onmatch="exclude">\n        <Image condition="is">C:\\Program Files\\Palo Alto Networks\\Traps\\cyserver.exe</Image>        <!--Credit d4ph1l -->\n      </NetworkConnect>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>\n', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="Exclude_UDP" groupRelation="or">\r\n      <NetworkConnect onmatch="exclude">\r\n        <Rule groupRelation="and">\r\n          <Protocol condition="is">udp</Protocol>\r\n          <DestinationPort condition="is">3389</DestinationPort>\r\n        </Rule>\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="exclude">\r\n        <Image condition="is">C:\\Program Files (x86)\\Sophos\\Sophos Anti-Virus\\Web Intelligence\\swi_service.exe</Image>        <!--Credit d4ph1l -->\r\n        <Image condition="is">C:\\Program Files (x86)\\Sophos\\AutoUpdate\\ALsvc.exe</Image>        <!--Credit d4ph1l -->\r\n        <Image condition="is">C:\\Program Files (x86)\\Sophos\\Remote Management System\\RouterNT.exe</Image>        <!--Credit d4ph1l -->\r\n        <Image condition="is">C:\\Program Files (x86)\\Sophos\\Sophos Anti-Virus\\Web Control\\swc_service.exe</Image>        <!--Credit d4ph1l -->\r\n        <Image condition="is">C:\\Program Files (x86)\\Sophos\\Sophos Anti-Virus\\Web Intelligence\\swi_service.exe</Image>        <!--Credit d4ph1l -->\r\n        <Image condition="is">C:\\Program Files\\Sophos\\Sophos Network Threat Protection\\bin\\SntpService.exe</Image>        <!--Credit d4ph1l -->\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="exclude">\r\n        <Image condition="end with">AppData\\Roaming\\Spotify\\Spotify.exe</Image>        <!--Spotify-->\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>', '<Sysmon schemaversion="4.30">\n    <EventFiltering>\n        <RuleGroup name="" groupRelation="or">\n            <NetworkConnect onmatch="exclude">\n                <Image condition="end with">AppData\\Local\\SynologyDrive\\SynologyDrive.app\\bin\\cloud-drive-ui.exe</Image>                <!--SynologyDrive-->\n                <Image condition="end with">AppData\\Local\\SynologyDrive\\SynologyDrive.app\\bin\\cloud-drive-daemon.exe</Image>                <!--SynologyDrive-->\n            </NetworkConnect>\n        </RuleGroup>\n    </EventFiltering>\n</Sysmon>', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="exclude">\r\n        <Image condition="is">C:\\Program files (x86)\\Trend Micro\\OfficeScan Client\\tmlisten.exe</Image>        <!--Credit d4ph1l -->\r\n        <Image condition="is">C:\\Program Files (x86)\\Trend Micro\\BM\\TMBMSRV.exe</Image>        <!--Credit d4ph1l -->\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="exclude">\r\n\t\t\t\t<!--SECTION: Microsoft-->\r\n\t\t\t\t<DestinationHostname condition="end with">.windowsupdate.microsoft.com</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t\t<DestinationHostname condition="end with">.windowsupdate.com</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t\t<DestinationHostname condition="end with">wustat.windows.com</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t\t<DestinationHostname condition="end with">go.microsoft.com</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t\t<DestinationHostname condition="end with">.update.microsoft.com</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t\t<DestinationHostname condition="end with">download.microsoft.com</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t\t<DestinationHostname condition="end with">microsoft.com.akadns.net</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t\t<DestinationHostname condition="end with">microsoft.com.nsatc.net</DestinationHostname>\t\t\t\t<!--Microsoft:Update delivery-->\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="include">\r\n\t\t\t\t<!--3rd Party Remote Management tools-->\r\n\t\t\t\t<Image name="technique_id=T1021,technique_name=Remote Services" condition="image">vnc.exe</Image>\t\t\t\t<!-- VNC client | Credit @Cyb3rOps -->\r\n\t\t\t\t<Image name="technique_id=T1021,technique_name=Remote Services" condition="image">vncviewer.exe</Image>\t\t\t\t<!-- VNC client | Credit @Cyb3rOps -->\r\n\t\t\t\t<Image name="technique_id=T1021,technique_name=Remote Services" condition="image">vncservice.exe</Image>\t\t\t\t<!-- VNC server | Credit @Cyb3rOps -->\r\n\t\t\t\t<Image name="technique_id=T1569.002,technique_name=Service Execution" condition="image">winexesvc.exe</Image>\t\t\t\t<!-- Winexe service executable | Credit @Cyb3rOps -->\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="include">\r\n        <Image name="technique_id=T1197,technique_name=BITS Jobs" condition="image">bitsadmin.exe</Image>\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\n  <EventFiltering>\n    <RuleGroup name="technique_id=T1571,technique_name=Non-Standard Port" groupRelation="or">\n      <NetworkConnect onmatch="include">\n        <DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">4444</DestinationPort>      <!--Metasploit-based reverse shells-->\n        <DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">31337</DestinationPort>     <!--Back Orifice, BO2K-->\n        <DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">6667</DestinationPort>     <!--IRC-based botnets-->\n        <DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">5555</DestinationPort>     <!--Satori, ADB.Miner-->\n        <DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">5353</DestinationPort>     <!--DNSMessenger-->\n      </NetworkConnect>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="include">\r\n\t\t\t\t<!--Critical HP services-->\r\n\t\t\t\t<Image name="technique_id=T1021,technique_name=Remote Services" condition="image">omniinet.exe</Image>\t\t\t\t<!-- HP Data Protector https://www.cvedetails.com/vulnerability-list/vendor_id-10/product_id-20499/HP-Data-Protector.html | Credit @Cyb3rOps -->\r\n\t\t\t\t<Image name="technique_id=T1021,technique_name=Remote Services" condition="image">hpsmhd.exe</Image>\t\t\t\t<!-- HP System Management Homepage https://www.cvedetails.com/vulnerability-list/vendor_id-10/product_id-7244/HP-System-Management-Homepage.html | Credit @Cyb3rOps -->\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\n  <EventFiltering>\n    <RuleGroup name="" groupRelation="or">\n      <NetworkConnect onmatch="include">\n        <Image name="technique_id=T1102,technique_name=Web Service" condition="begin with">C:\\Program Files\\Microsoft\\HybridConnectionManager</Image>        <!--https://twitter.com/_dirkjan/status/1381591080207015936-->\n      </NetworkConnect>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>\n', '<Sysmon schemaversion="4.40">\n  <EventFiltering>\n    <RuleGroup name="" groupRelation="or">\n      <NetworkConnect onmatch="include">\n        <!-- Native Windows tools - Living off the land -->\n        <!-- Research needed on how many of these tools are capable of making a network connection - see ipconfig.exe -->\n        <Rule name="Unusual Connection" groupRelation="or">\n          <Image condition="image">dllhost.exe</Image>\n          <Image condition="image">hh.exe</Image>          <!--Microsoft:Windows: HTML Helper-->\n          <Image condition="image">klist.exe</Image>          <!--Microsoft:Windows: show cached kerberos tickets -->\n          <Image condition="image">schtasks.exe</Image>          <!--Microsoft:Windows: Command and Scripting Interpreter to local and remote tasks -->\n          <Image condition="image">taskkill.exe</Image>          <!--Microsoft:Windows: Kill processes, has remote ability -->\n          <Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>\n          <Image name="technique_id=T1218.010,technique_name=Regsvr32" condition="image">regsvr32.exe</Image>          <!--Mitre T1218.010-->          <!--Mitre T1218.011-->          <!--Microsoft:Windows: [ https://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html ] -->\n          <Image name="technique_id=T1518.001,technique_name=Security Software Discovery" condition="image">netsh.exe</Image>          <!--Mitre T1016-->          <!--Mitre T1546.007-->          <!--Mitre T1518.001-->          <!--Microsoft:Windows: manipulate the firewall -->\n          <Image name="technique_id=T1548.002,technique_name=Bypass User Access Control" condition="image">xwizard.exe</Image>          <!--https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/ -->\n          <Image name="technique_id=T1564.004,technique_name=NTFS File Attributes" condition="image">esentutl.exe</Image>          <!--https://lolbas-project.github.io/lolbas/Binaries/Esentutl/ Multiple options-->\n          <Image name="technique_id=T1112,technique_name=Modify Registry" condition="image">reg.exe</Image>          <!--Mitre T1552.002-->          <!--Mitre T1012-->          <!--Mitre T1112-->          <!--Microsoft:Windows: reads and modifies the Windows register -->\n          <Image name="technique_id=T1134,technique_name=Access Token Manipulation" condition="image">runas.exe</Image>          <!--Microsoft:Windows: run a process as another user -->\n          <Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">net1.exe</Image>          <!--Mitre T1018-->          <!--Mitre T1021.002-->          <!--Mitre T1087-->          <!--Mitre T1135-->          <!--Mitre T1069-->          <!--Mitre T1016-->          <!--Microsoft:Windows: Launched by "net.exe", but it may not detect connections either -->\n          <Image name="technique_id=T1070,technique_name=Indicator Removal on Host" condition="image">wevtutil.exe</Image>          <!--Microsoft:Windows: read and modify the Windows Eventlog -->\n        </Rule>\n        <Image name="technique_id=T1003,technique_name=Credential Dumping" condition="image">RpcPing.exe</Image>        <!--https://lolbas-project.github.io/lolbas/Binaries/Rpcping/ -->\n        <Rule name="Discovery" groupRelation="or">\n          <Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">ipconfig.exe</Image>          <!--Microsoft:Windows: shows ip configuration -->\n          <Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">nbtstat.exe</Image>          <!--Microsoft:Windows: NetBIOS statistics, attackers use to enumerate local network -->\n          <Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">nslookup.exe</Image>          <!--Microsoft:Windows: shows DNS configuration and enables quering -->\n          <Image name="technique_id=T1018,technique_name=Remote System Discovery" condition="image">net.exe</Image>          <!--Mitre T1201-->          <!--Mitre T1007-->          <!--Mitre T1124-->          <!--Mitre T1018-->          <!--Mitre T1049-->          <!--Mitre T1087-->          <!--Mitre T1135-->          <!--Mitre T1069-->          <!--Mitre T1016-->          <!--Mitre T1021.002-->          <!--Microsoft:Windows: "net use"/"net view" used by attackers to surveil and connect with file shares from command line | Credit @ion-storm -->\n          <Image name="technique_id=T1018,technique_name=Remote System Discovery" condition="image">nslookup.exe</Image>          <!--Microsoft:Windows: Retrieve data over DNS -->\n          <Image name="technique_id=T1033,technique_name=System Owner/User Discovery" condition="image">nltest.exe</Image>          <!-- netlogon testing utility-->\n          <Image name="technique_id=T1033,technique_name=System Owner/User Discovery" condition="image">quser.exe</Image>          <!--Microsoft:Windows: shows logged-on users -->\n          <Image name="technique_id=T1049,technique_name=System Network Connections Discovery" condition="image">netstat.exe</Image>          <!--Mitre T1016-->          <!--Mitre T1049-->          <!--Microsoft:Windows: shows protocol statistics and current TCP/IP network connections -->\n          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qprocess.exe</Image>          <!--Microsoft:Windows: shows information about processes -->\n          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">query.exe</Image>          <!--Microsoft:Windows: shows information about processes -->\n          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qwinsta.exe</Image>          <!--Microsoft:Windows: Remotely query login sessions on a server or workstation | Credit @ion-storm -->\n          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">rwinsta.exe</Image>          <!--Microsoft:Windows: Disconnect remote sessions | Credit @ion-storm -->\n          <Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">tasklist.exe</Image>          <!--Mitre T1057-->          <!--Mitre T1007-->          <!--Microsoft:Windows: shows current running processes-->\n        </Rule>\n        <Rule name="Ingress Tool Transfer" groupRelation="or">\n          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">expand.exe</Image>\n          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">extrac32.exe</Image>\n          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">IEExec.exe</Image>\n          <Image name="technique_id=T1105,technique_name=Ingress Tool Transfer" condition="image">Print.Exe</Image>\n        </Rule>\n        <Rule name="Execution" groupRelation="or">\n          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">cscript.exe</Image>\n          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">desktopimgdownldr.exe</Image>          <!--https://labs.sentinelone.com/living-off-windows-land-a-new-native-file-downldr/-->\n          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">pcalua.exe</Image>          <!--Microsoft:Windows: Program Compatibility Assistant)-->\n          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">winrs.exe</Image>\n          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">wscript.exe</Image>\n          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">Msdt.exe</Image>          <!--https://lolbas-project.github.io/lolbas/Binaries/Msdt/-->\n          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msiexec.exe</Image>\n          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">RegisterCimProvider.exe</Image>\n          <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">ScriptRunner.exe</Image>\n          <Image name="technique_id=T1127,technique_name=Trusted Developer Utilities Proxy Execution" condition="image">dfsvc.exe</Image>          <!--https://lolbas-project.github.io/lolbas/Binaries/Dfsvc/-->\n        </Rule>\n        <Rule name="Services" groupRelation="or">\n          <Image name="technique_id=T1569.002,technique_name=Service Execution" condition="image">dnscmd.exe</Image>          <!-- Service Execution https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/ -->\n          <Image name="technique_id=T1543.003,technique_name=Windows Service" condition="image">sc.exe</Image>\n          <Image name="technique_id=T1053,technique_name=Scheduled Task/Job" condition="image">taskeng.exe</Image>          <!--Microsoft:Windows: taskscheduler -->\n        </Rule>\n        <Rule name="Shells and Terminals" groupRelation="or">\n          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">OpenConsole.exe</Image>          <!--Microsoft Windows Terminal-->\n          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">powershell.exe</Image>          <!--Microsoft:Windows: PowerShell interface-->\n          <Image name="technique_id=T1059.001,technique_name=PowerShell" condition="image">WindowsTerminal.exe</Image>          <!--Microsoft Windows Terminal-->\n          <Image name="technique_id=T1059.003,technique_name=Windows Command Shell" condition="image">cmd.exe</Image>          <!--Microsoft:Windows: Command prompt-->\n          <Image name="technique_id=T1202,technique_name=Indirect Command Execution" condition="image">bash.exe</Image>          <!--Microsoft:Windows: bash on Windows, Linux subsystem-->\n        </Rule>\n      </NetworkConnect>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>\n', '<Sysmon schemaversion="4.30">\n  <EventFiltering>\n    <RuleGroup name="" groupRelation="or">\n      <NetworkConnect onmatch="include">\n        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">Mavinject.exe</Image>\n      </NetworkConnect>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="include">\r\n\t\t\t\t<!--Native Windows tools - Living off the land-->\r\n\t\t\t\t<Image name="technique_id=T1053,technique_name=Scheduled Task" condition="image">at.exe</Image>\t\t\t\t<!--Microsoft:Windows: Remote task scheduling | Credit @ion-storm -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">certutil.exe</Image>\t\t\t\t<!--Microsoft:Windows: Certificate tool can contact outbound | Credit @ion-storm and @FVT [ https://twitter.com/FVT/status/834433734602530817 ] -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Signed Script Proxy Execution" condition="image">cscript.exe</Image>\t\t\t\t<!--Microsoft:WindowsScriptingHost: | Credit @Cyb3rOps [ https://gist.github.com/Neo23x0/a4b4af9481e01e749409 ] -->\r\n\t\t\t\t<Image condition="image">java.exe</Image>\t\t\t\t<!--Java: Monitor usage of vulnerable application | Credit @ion-storm -->\r\n\t\t\t\t<Image name="technique_id=T1218.005,technique_name=Mshta" condition="image">mshta.exe</Image>\t\t\t\t<!--Microsoft:Windows: HTML application executes scripts without IE protections | Credit @ion-storm [ https://en.wikipedia.org/wiki/HTML_Application ] -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msiexec.exe</Image>\t\t\t\t<!--Microsoft:Windows: Can install from http:// paths | Credit @vector-sec -->\r\n\t\t\t\t<Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">net.exe</Image>\t\t\t\t<!--Mitre T1018-->\t\t\t\t<!--Mitre T1021.002-->\t\t\t\t<!--Mitre T1087-->\t\t\t\t<!--Mitre T1135-->\t\t\t\t<!--Mitre T1069-->\t\t\t\t<!--Mitre T1016-->\t\t\t\t<!--Microsoft:Windows: "net use"/"net view" used by attackers to surveil and connect with file shares from command line | Credit @ion-storm -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">notepad.exe</Image>\t\t\t\t<!--Microsoft:Windows: [ https://blog.cobaltstrike.com/2013/08/08/why-is-notepad-exe-connecting-to-the-internet/ ] -->\r\n\t\t\t\t<Image name="technique_id=T1012,technique_name=Query Registry" condition="image">reg.exe</Image>\t\t\t\t<!--Mitre T1012-->\t\t\t\t<!--Mitre T1112-->\t\t\t\t<!--Microsoft:Windows: Remote Registry | Credit @ion-storm -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Regsvr32" condition="image">regsvr32.exe</Image>\t\t\t\t<!--Microsoft:Windows: [ https://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html ] -->\r\n\t\t\t\t<Image name="technique_id=T1218.011,technique_name=Rundll32" condition="image">rundll32.exe</Image>\t\t\t\t<!--Microsoft:Windows: [ https://blog.cobaltstrike.com/2016/07/22/why-is-rundll32-exe-connecting-to-the-internet/ ] -->\r\n\t\t\t\t<Image name="technique_id=T1543.003,technique_name=Windows Service" condition="image">sc.exe</Image>\t\t\t\t<!--Microsoft:Windows: Remotely change Windows service settings from command line | Credit @ion-storm -->\r\n\t\t\t\t<Image name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="image">wmic.exe</Image>\t\t\t\t<!--T1047-->\t\t\t\t<!--Mitre T1135-->\t\t\t\t<!--Microsoft:WindowsManagementInstrumentation: Credit @Cyb3rOps [ https://gist.github.com/Neo23x0/a4b4af9481e01e749409 ] -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Signed Script Proxy Execution" condition="image">wscript.exe</Image>\t\t\t\t<!--Microsoft:WindowsScriptingHost: | Credit @arekfurt -->\r\n\t\t\t\t<Image condition="image">driverquery.exe</Image>\t\t\t\t<!--Microsoft:Windows: Remote recognisance of system configuration, oudated/vulnerable drivers -->\r\n\t\t\t\t<Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">dsquery.exe</Image>\t\t\t\t<!--Microsoft: Query Active Directory -->\r\n\t\t\t\t<Image name="technique_id=T1069,technique_name=Permission Groups Discovery" condition="image">AdFind.exe</Image>\r\n\t\t\t\t<Image condition="image">hh.exe</Image>\t\t\t\t<!--Microsoft:Windows: HTML Help Executable, opens CHM files -->\r\n\t\t\t\t<Image condition="image">infDefaultInstall.exe</Image>\t\t\t\t<!--Microsoft: [ https://github.com/huntresslabs/evading-autoruns ] | Credit @KyleHanslovan -->\r\n\t\t\t\t<Image condition="image">javaw.exe</Image>\t\t\t\t<!--Java: Monitor usage of vulnerable application and init from JAR files -->\r\n\t\t\t\t<Image condition="image">javaws.exe</Image>\t\t\t\t<!--Java: Monitor usage of vulnerable application and init from JAR files -->\r\n\t\t\t\t<Image name="technique_id=T1543.003,technique_name=Windows Service" condition="image">mmc.exe</Image>\t\t\t\t<!--Microsoft:Windows: -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">msbuild.exe</Image>\t\t\t\t<!--Microsoft:Windows: [ https://www.hybrid-analysis.com/sample/a314f6106633fba4b70f9d6ddbee452e8f8f44a72117749c21243dc93c7ed3ac?environmentId=100 ] -->\r\n\t\t\t\t<Image name="technique_id=T1016,technique_name=System Network Configuration Discovery" condition="image">nbtstat.exe</Image>\t\t\t\t<!--Microsoft:Windows: NetBIOS statistics, attackers use to enumerate local network -->\r\n\t\t\t\t<Image name="technique_id=T1018,technique_name=Remote System Discovery" condition="image">nslookup.exe</Image>\t\t\t\t<!--Microsoft:Windows: Retrieve data over DNS -->\r\n\t\t\t\t<Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qprocess.exe</Image>\t\t\t\t<!--Microsoft:Windows: [ https://www.first.org/resources/papers/conf2017/APT-Log-Analysis-Tracking-Attack-Tools-by-Audit-Policy-and-Sysmon.pdf ] -->\r\n\t\t\t\t<Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">qwinsta.exe</Image>\t\t\t\t<!--Microsoft:Windows: Remotely query login sessions on a server or workstation | Credit @ion-storm -->\r\n\t\t\t\t<Image name="technique_id=T1218.009,technique_name=Regsvcs/Regasm" condition="image">regsvcs.exe</Image>\t\t\t\t<!--Microsoft:Windows: [ https://www.hybrid-analysis.com/sample/3f94d7080e6c5b8f59eeecc3d44f7e817b31562caeba21d02ad705a0bfc63d67?environmentId=100 ] -->\r\n\t\t\t\t<Image name="technique_id=T1057,technique_name=Process Discovery" condition="image">rwinsta.exe</Image>\t\t\t\t<!--Microsoft:Windows: Disconnect remote sessions | Credit @ion-storm -->\r\n\t\t\t\t<Image name="technique_id=T1053,technique_name=Scheduled Task/Job" condition="image">schtasks.exe</Image>\t\t\t\t<!--Microsoft:Windows: Command and Scripting Interpreter to local and remote tasks -->\r\n\t\t\t\t<Image name="technique_id=T1562.001,technique_name=Disable or Modify Tools" condition="image">taskkill.exe</Image>\t\t\t\t<!--Microsoft:Windows: Kill processes, has remote ability -->\r\n\t\t\t\t<Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">replace.exe</Image>\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="include">\r\n\t\t\t\t<!--Ports: Proxy-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">1080</DestinationPort>\t\t\t\t<!--Socks proxy port | Credit @ion-storm-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">3128</DestinationPort>\t\t\t\t<!--Socks proxy port | Credit @ion-storm-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">8080</DestinationPort>\t\t\t\t<!--Socks proxy port | Credit @ion-storm-->\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="include">\r\n\t\t\t\t<!--Eventhough DNS is a commmon exfil channel, you should monitor that via some other way, Sysmon is not ideal for that-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">22</DestinationPort>\t\t\t\t<!--SSH protocol-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">23</DestinationPort>\t\t\t\t<!--Telnet protocol-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">25</DestinationPort>\t\t\t\t<!--SMTP mail protocol-->\r\n\t\t\t\t<Rule groupRelation="and">\r\n\t\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">88</DestinationPort>\t\t\t\t<!--Kerberos protocol-->\r\n\t\t\t\t\t<Image condition="is not">C:\\Windows\\System32\\lsass.exe</Image>\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t<!--exclude LSASS for Kerberos protocol-->\r\n        \t\t</Rule>\r\n\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">3389</DestinationPort>\t\t\t\t<!--Microsoft:Windows:RDP-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5800</DestinationPort>\t\t\t\t<!--VNC protocol-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5900</DestinationPort>\t\t\t\t<!--VNC protocol-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5985</DestinationPort>\t\t\t\t<!--WinRM protocol-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1021,technique_name=Remote Services" condition="is">5986</DestinationPort>\t\t\t\t<!--WinRM protocol-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1087.002,technique_name=Account Discovery: Domain Account" condition="is">9389</DestinationPort>\t\t\t\t<!--ADWS port-->\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="include">\r\n        <Image name="technique_id=T1569.002,technique_name=Service Execution" condition="image">psexec.exe</Image>        <!--Sysinternals:PsExec client side | Credit @Cyb3rOps -->\r\n        <Image name="technique_id=T1569.002,technique_name=Service Execution" condition="image">psexesvc.exe</Image>        <!--Sysinternals:PsExec server side | Credit @Cyb3rOps -->\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="include">\r\n\t\t\t\t<Rule groupRelation="and">\r\n\t\t\t\t\t<SourcePort name="technique_id=T1557,technique_name=Adversary-in-the-Middle" condition="is any">445;389;8492;636;3268;3269</SourcePort>\r\n\t\t\t\t\t<Image condition="is not">C:\\Windows\\System32\\lsass.exe</Image>\r\n        \t\t\t<Image condition="is not">c:\\Windows\\System32\\dsamain.exe</Image>\r\n        \t\t\t<ProcessId condition="is not">4</ProcessId>\r\n        \t\t</Rule>\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="include">\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Users</Image>        <!--Tools downloaded by users can use other processes for networking, but this is a very valuable indicator.-->\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\ProgramData</Image>        <!--Normally, network communications should be sourced from "Program Files" not from ProgramData, something to look at-->\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\Temp</Image>        <!--Suspicious anything would communicate from the system-level temp directory-->\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Temp</Image>        <!--Suspicious anything would communicate from the temp directory-->\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\PerfLogs\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\$Recycle.bin\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Intel\\Logs\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Users\\Default\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Users\\Public\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Users\\NetworkService\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\Fonts\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\Debug\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\Media\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\Help\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\addins\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\repair\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\security\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="begin with">C:\\Windows\\system32\\config\\systemprofile\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\htdocs\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\wwwroot\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\AppData\\Local\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\AppData\\Local\\Temp\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\AppData\\Roaming\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">\\AppData\\LocalLow\\</Image>\r\n        <Image name="technique_id=T1036,technique_name=Masquerading" condition="contains">C:\\Windows\\SysWOW64</Image>\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\n  <EventFiltering>\n    <RuleGroup name="" groupRelation="or">\n      <NetworkConnect onmatch="include">\n        <Image name="technique_id=T1218,technique_name=Signed Binary Proxy Execution" condition="image">SyncAppvPublishingServer.exe</Image>\n      </NetworkConnect>\n    </RuleGroup>\n  </EventFiltering>\n</Sysmon>\n', '<Sysmon schemaversion="4.30">\r\n\t<EventFiltering>\r\n\t\t<RuleGroup name="" groupRelation="or">\r\n\t\t\t<NetworkConnect onmatch="include">\r\n\t\t\t\t<!--TOR - Frequently used by malware-->\r\n\t\t\t\t<Image condition="image">tor.exe</Image>\t\t\t\t<!--Tor [ https://www.hybrid-analysis.com/sample/800bf028a23440134fc834efc5c1e02cc70f05b2e800bbc285d7c92a4b126b1c?environmentId=100 ] -->\r\n\t\t\t\t<!--Ports: Tor-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">1723</DestinationPort>\t\t\t\t<!--Tor protocol | Credit @ion-storm-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">4500</DestinationPort>\t\t\t\t<!--Tor protocol | Credit @ion-storm-->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">9001</DestinationPort>\t\t\t\t<!--Tor protocol [ http://www.computerworlduk.com/tutorial/security/tor-enterprise-2016-blocking-malware-darknet-use-rogue-nodes-3633907/ ] -->\r\n\t\t\t\t<DestinationPort name="technique_id=T1571,technique_name=Non-Standard Port" condition="is">9030</DestinationPort>\t\t\t\t<!--Tor protocol [ http://www.computerworlduk.com/tutorial/security/tor-enterprise-2016-blocking-malware-darknet-use-rogue-nodes-3633907/ ] -->\r\n\t\t\t</NetworkConnect>\r\n\t\t</RuleGroup>\r\n\t</EventFiltering>\r\n</Sysmon>\r\n', '<Sysmon schemaversion="4.30">\r\n  <EventFiltering>\r\n    <RuleGroup name="" groupRelation="or">\r\n      <NetworkConnect onmatch="include">\r\n        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5985</DestinationPort>\r\n        <DestinationPort name="technique_id=T1021.006,technique_name=Windows Remote Management" condition="is">5986</DestinationPort>\r\n      </NetworkConnect>\r\n    </RuleGroup>\r\n  </EventFiltering>\r\n</Sysmon>\r\n']

Instruction:
Based on the security analysis previously done before and the host state:

The host's: 
	installed programs: ['Docker Desktop (v4.75.0)', 'Git (v2.54.0)', 'Mozilla Firefox (x64 en-GB) (v152.0)', 'Mozilla Maintenance Service (v150.0.3)', 'Microsoft 365 Apps for enterprise - en-us (v16.0.20026.20168)', 'Microsoft OneDrive (v26.098.0524.0004)', 'Sublime Text ', 'TeXstudio - TeXstudio is a fully featured LaTeX editor. (v4.9.4)', 'Zotero (v9.0.5)', 'Windows Subsystem for Linux (v2.7.3.0)', 'Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211 (v14.44.35211)', 'Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211 (v14.44.35211)', 'Office 16 Click-to-Run Extensibility Component (v16.0.20026.20076)', 'Microsoft Teams Meeting Add-in for Microsoft Office (v1.26.11802)', 'Copilot (v149.0.4022.66)', 'Microsoft Edge (v149.0.4022.69)', 'Microsoft Edge WebView2 Runtime (v149.0.4022.69)', 'Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.44.35211 (v14.44.35211.0)', 'Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.44.35211 (v14.44.35211)', 'Microsoft Visual C++ 2022 X86 Additional Runtime - 14.44.35211 (v14.44.35211)', 'Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.44.35211 (v14.44.35211.0)', 'MiKTeX (v25.12)', 'Python 3.14.5 (v3.14-64)', 'Ollama version 0.30.8 (v0.30.8)', 'MiKTeX (v25.12)', 'Python 3.14.5 (v3.14-64)', 'Ollama version 0.30.8 (v0.30.8)']
	services: ['AppIDSvc', 'Appinfo', 'AppXSvc', 'AudioEndpointBuilder', 'Audiosrv', 'BFE', 'BrokerInfrastructure', 'BTAGService', 'BthAvctpSvc', 'bthserv', 'camsvc', 'CDPSvc', 'CertPropSvc', 'ClickToRunSvc', 'ClipSVC', 'CoreMessagingRegistrar', 'cplspcon', 'CryptSvc', 'DcomLaunch', 'DeviceAssociationService', 'DevQueryBroker', 'Dhcp', 'DiagTrack', 'DispBrokerDesktopSvc', 'DisplayEnhancementService', 'Dnscache', 'DolbyDAXAPI', 'DolbyFusionAPI', 'DoSvc', 'DPS', 'dptftcs', 'DsSvc', 'DusmSvc', 'EPDService', 'EventLog', 'EventSystem', 'FontCache', 'gpsvc', 'hidserv', 'hns', 'HvHost', 'IBMPMSVC', 'InstallService', 'IntelAudioService', 'IntelCstService', 'InventorySvc', 'ipfsvc', 'iphlpsvc', 'jhi_service', 'KeyIso', 'LanmanServer', 'LanmanWorkstation', 'LenovoSmartStandby', 'lfsvc', 'LicenseManager', 'LITSSVC', 'lmhosts', 'LMS', 'LSM', 'LvfInstallService', 'MDCoreSvc', 'mpssvc', 'NcbService', 'netprofm', 'nsi', 'nvagent', 'PcaSvc', 'PhoneSvc', 'PlugPlay', 'Power', 'ProfSvc', 'RasMan', 'RmSvc', 'RpcEptMapper', 'RpcSs', 'RtkAudioUniversalService', 'SamSs', 'SCardSvr', 'Schedule', 'SecurityHealthService', 'SENS', 'SensorService', 'SharedAccess', 'ShellHWDetection', 'SmartSense', 'Spooler', 'SSDPSRV', 'SstpSvc', 'StateRepository', 'StorSvc', 'SynHsaService', 'SysMain', 'Sysmon64', 'SystemEventsBroker', 'TextInputManagementService', 'Themes', 'TimeBrokerSvc', 'TokenBroker', 'TPHKLOAD', 'TrkWks', 'UserManager', 'UsoSvc', 'VaultSvc', 'Wcmsvc', 'WdiSystemHost', 'WdNisSvc', 'webthreatdefsvc', 'whesvc', 'WinDefend', 'WinHttpAutoProxySvc', 'Winmgmt', 'WlanSvc', 'WMIRegistrationService', 'WpnService', 'WSAIFabricSvc', 'wscsvc', 'WSearch', 'WSLService', 'wuqisvc', 'BluetoothUserService_1e96c8f', 'cbdhsvc_1e96c8f', 'CDPUserSvc_1e96c8f', 'DevicesFlowUserSvc_1e96c8f', 'NPSMSvc_1e96c8f', 'UdkUserSvc_1e96c8f', 'webthreatdefusersvc_1e96c8f', 'WpnUserService_1e96c8f']
	running processes: [None, '', 'Registry', 'C:\\Program Files\\Mozilla Firefox\\firefox.exe', 'C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\realtekservice.inf_amd64_6477ac83bad98f87\\RtkAudUService64.exe', 'C:\\Windows\\System32\\smss.exe', 'C:\\Windows\\System32\\csrss.exe', 'C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\149.0.4022.69\\msedgewebview2.exe', 'C:\\Windows\\System32\\wininit.exe', 'C:\\Windows\\System32\\services.exe', 'C:\\Windows\\System32\\LsaIso.exe', 'C:\\Windows\\System32\\lsass.exe', 'C:\\Windows\\System32\\fontdrvhost.exe', 'C:\\Windows\\System32\\WUDFHost.exe', 'C:\\Windows\\System32\\backgroundTaskHost.exe', 'C:\\Windows\\System32\\RuntimeBroker.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\DAX3_S~1.INF\\DAX3API.exe', 'C:\\Program Files\\WindowsApps\\MSTeams_26134.1702.4747.7366_x64__8wekyb3d8bbwe\\ms-teams.exe', 'C:\\Windows\\explorer.exe', 'C:\\Program Files\\Sublime Text\\plugin_host-3.8.exe', 'C:\\Windows\\System32\\taskhostw.exe', 'C:\\Program Files\\Sublime Text\\crash_handler.exe', 'C:\\Windows\\System32\\dllhost.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\iigd_dch.inf_amd64_6c0a5016a1917804\\IntelCpHDCPSvc.exe', 'MemCompression', 'C:\\Windows\\System32\\EPDService.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\lnvvsndmft.inf_amd64_f6d79d78edcb4315\\LvfInstallService.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\litsdrv.inf_amd64_0fefde8b58482d0b\\x64\\LITSSvc.exe', 'C:\\Program Files\\Mozilla Firefox\\crashhelper.exe', 'C:\\Windows\\System32\\EPDCtrl.exe', 'C:\\Windows\\System32\\spoolsv.exe', 'C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26050.15-0\\MpDefenderCoreService.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\intcoed.inf_amd64_5e376a2004e773e8\\AS\\IAS\\IntelAudioService.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\dtt_sw.inf_amd64_5ecafabf5082a9c7\\ipfsvc.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\dal.inf_amd64_8a3f88e34f6b8385\\jhi_service.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\dax3_swc_aposvc.inf_amd64_6c19a4caad42dde0\\DAX3API.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\fusion_swc_aposvc.inf_amd64_210bb9e65957d54a\\FusionAPI.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\smartstandbycomponent.inf_amd64_3d585c065d8f0236\\SmartStandby.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ipf_cpu.inf_amd64_049e38a37c46edc4\\ipf_uf.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\lms.inf_amd64_a0f482a0fd3e2e74\\LMS.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ibmpmdrv.inf_amd64_317aadafb86018c3\\x64\\ibmpmsvc.exe', 'C:\\Windows\\Sysmon64.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26050.15-0\\MsMpEng.exe', 'C:\\Program Files\\WSL\\wslservice.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\mewmiprov.inf_amd64_d7a222f6ce13d429\\WMIRegistrationService.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\synawudfbiousbuwp.inf_amd64_2b0e80551ca8c54d\\SynRpcServer.exe', 'C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\CrossDeviceResume.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\fn.inf_amd64_8e91a39d67d49dc4\\driver\\tphkload.exe', 'C:\\Windows\\System32\\wbem\\unsecapp.exe', 'C:\\Windows\\System32\\DataExchangeHost.exe', 'C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe', 'C:\\Windows\\System32\\AggregatorHost.exe', 'C:\\Windows\\System32\\wlanext.exe', 'C:\\Program Files\\WindowsApps\\RealtekSemiconductorCorp.RealtekAudioControl_1.1.137.0_x64__dt26b99r8h8gj\\RtkUWP.exe', 'C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.24.11321.0_x64__8wekyb3d8bbwe\\OpenConsole.exe', 'C:\\Program Files\\WindowsApps\\Microsoft.WidgetsPlatformRuntime_1.6.19.0_x64__8wekyb3d8bbwe\\WidgetService\\WidgetService.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\icst_service.inf_amd64_f498e59a9fa69db3\\intel_cst_service_standalone.exe', 'C:\\Windows\\SystemApps\\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\\StartMenuExperienceHost.exe', 'C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe', 'C:\\Windows\\System32\\SearchIndexer.exe', 'C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\SearchHost.exe', 'C:\\Windows\\System32\\dwm.exe', 'C:\\Program Files\\WindowsApps\\PythonSoftwareFoundation.PythonManager_26.2.240.0_x64__3847v3x7pw1km\\python.exe', 'C:\\Windows\\System32\\winlogon.exe', 'C:\\Program Files\\Microsoft OneDrive\\26.098.0524.0004\\OneDrive.Sync.Service.exe', 'C:\\Windows\\SystemApps\\ShellExperienceHost_cw5n1h2txyewy\\ShellExperienceHost.exe', 'C:\\Windows\\System32\\ApplicationFrameHost.exe', 'C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\ImmersiveControlPanel\\SystemSettings.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\lnvsst.inf_amd64_e8bc61a910ff2d5f\\UserSSCtrl.exe', 'C:\\Windows\\SystemApps\\Microsoft.LockApp_cw5n1h2txyewy\\LockApp.exe', 'C:\\Program Files\\Sublime Text\\plugin_host-3.3.exe', 'C:\\Windows\\System32\\SecurityHealthService.exe', 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.26050.15-0\\NisSrv.exe', 'C:\\Windows\\System32\\sihost.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\ipf_cpu.inf_amd64_049e38a37c46edc4\\ipf_helper.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'C:\\Program Files\\Sublime Text\\sublime_text.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\FN2033~1.INF\\driver\\shtctky.exe', 'C:\\Users\\Paulo\\AppData\\Local\\Programs\\Ollama\\ollama app.exe', 'C:\\Windows\\System32\\conhost.exe', 'C:\\Program Files\\WindowsApps\\Microsoft.StartExperiencesApp_1.302.5.0_x64__8wekyb3d8bbwe\\MicrosoftStartFeedProvider\\MicrosoftStartFeedProvider.exe', 'C:\\Users\\Paulo\\AppData\\Local\\Programs\\Ollama\\ollama.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\FN2033~1.INF\\driver\\tposd.exe', 'C:\\Windows\\System32\\ShellHost.exe', 'C:\\Windows\\SystemApps\\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\\AppActions.exe', 'C:\\Users\\Paulo\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe', 'C:\\Program Files\\Microsoft OneDrive\\26.098.0524.0004\\FileCoAuth.exe', 'C:\\Program Files (x86)\\Microsoft\\Copilot\\Application\\mscopilot_proxy.exe', 'C:\\Windows\\System32\\DriverStore\\FileRepository\\lnvsst.inf_amd64_e8bc61a910ff2d5f\\SmartSense.exe', 'C:\\Windows\\System32\\ctfmon.exe', 'C:\\Windows\\System32\\SecurityHealthSystray.exe', 'C:\\Program Files\\WindowsApps\\MicrosoftWindows.Client.WebExperience_526.11701.50.0_x64__cw5n1h2txyewy\\WidgetBoard.exe', 'C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal_1.24.11321.0_x64__8wekyb3d8bbwe\\WindowsTerminal.exe', 'C:\\Windows\\System32\\audiodg.exe', 'C:\\Windows\\SysWOW64\\Lenovo\\PowerMgr\\PowerMgr.exe']
	ports: {'LISTEN': [{'laddr': addr(ip='::', port=445)}, {'laddr': addr(ip='::', port=7680)}, {'laddr': addr(ip='127.0.0.1', port=62275)}, {'laddr': addr(ip='0.0.0.0', port=623)}, {'laddr': addr(ip='::', port=49665)}, {'laddr': addr(ip='127.0.0.1', port=11434)}, {'laddr': addr(ip='::', port=49666)}, {'laddr': addr(ip='0.0.0.0', port=49664)}, {'laddr': addr(ip='::', port=49685)}, {'laddr': addr(ip='::', port=623)}, {'laddr': addr(ip='::1', port=42050)}, {'laddr': addr(ip='0.0.0.0', port=7680)}, {'laddr': addr(ip='::', port=49668)}, {'laddr': addr(ip='0.0.0.0', port=135)}, {'laddr': addr(ip='::', port=49664)}, {'laddr': addr(ip='::', port=49667)}, {'laddr': addr(ip='192.168.1.147', port=139)}, {'laddr': addr(ip='0.0.0.0', port=49685)}, {'laddr': addr(ip='0.0.0.0', port=16992)}, {'laddr': addr(ip='0.0.0.0', port=49667)}, {'laddr': addr(ip='0.0.0.0', port=5040)}, {'laddr': addr(ip='0.0.0.0', port=49668)}, {'laddr': addr(ip='0.0.0.0', port=49666)}, {'laddr': addr(ip='0.0.0.0', port=49665)}, {'laddr': addr(ip='::', port=135)}, {'laddr': addr(ip='::1', port=49669)}, {'laddr': addr(ip='0.0.0.0', port=445)}, {'laddr': addr(ip='::', port=16992)}], 'ESTABLISHED': [{'laddr': addr(ip='192.168.1.147', port=63405)}, {'raddr': addr(ip='2603:1063:13:10b::365:7ea3', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=61403)}, {'raddr': addr(ip='127.0.0.1', port=55141), 'laddr': addr(ip='127.0.0.1', port=55142)}, {'raddr': addr(ip='2603:1063:12:123::365:7ea3', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=63868)}, {'raddr': addr(ip='2603:1063:45::16', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=58255)}, {'raddr': addr(ip='2603:1063:12::306', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=51868)}, {'raddr': addr(ip='72.145.35.97', port=443), 'laddr': addr(ip='192.168.1.147', port=50994)}, {'raddr': addr(ip='2603:1063:12:124::365:7ea3', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=50103)}, {'raddr': addr(ip='2603:1026:c09:856::2', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=59931)}, {'raddr': addr(ip='127.0.0.1', port=49671), 'laddr': addr(ip='127.0.0.1', port=49670)}, {'raddr': addr(ip='127.0.0.1', port=55143), 'laddr': addr(ip='127.0.0.1', port=55144)}, {'raddr': addr(ip='127.0.0.1', port=55144), 'laddr': addr(ip='127.0.0.1', port=55143)}, {'raddr': addr(ip='2606:4700:440b::6812:2715', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=57708)}, {'raddr': addr(ip='127.0.0.1', port=55142), 'laddr': addr(ip='127.0.0.1', port=55141)}, {'raddr': addr(ip='140.82.113.26', port=443), 'laddr': addr(ip='192.168.1.147', port=62304)}, {'raddr': addr(ip='127.0.0.1', port=49670), 'laddr': addr(ip='127.0.0.1', port=49671)}, {'raddr': addr(ip='2603:1020:5:9::401', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=49417)}], 'TIME_WAIT': [{'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=50985)}, {'raddr': addr(ip='208.95.112.1', port=80), 'laddr': addr(ip='192.168.1.147', port=50989)}, {'raddr': addr(ip='2606:4700:78::90:0:183', port=443), 'laddr': addr(ip='2001:818:ea21:2800:2ce6:4cd5:c945:e4a6', port=50991)}]}



Provide a NetworkConnect snippet of the sysmon configuration file that would satisfy the requirements. 
Try to avoid isolate rules that can produce a lot of noise, like isolating port 8080 in an open include box.
Follow the example format and populate the name attribute of the tags with the corresponding technique_id and technique_name whenever applicable.
Use the xml comment syntax to refer the attack pattern or vulnerability being dealt with. And at the end of the XML file, still with the comment syntax, explain the what you used and not used from the security analysis.
Do NOT implement monitoring rules outside of the reported attack patterns: ['T1190', 'T1021.001', 'T1071.001', 'T1572', 'T1041', 'T1567']
		
```## Test case A answer
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190 & CVE-2023-48788: Monitor for outbound connections from suspected exploited processes -->
        <Rule groupRelation="and">
          <Image condition="image">w3wp.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1071.001, T1041, T1567: C2 and Exfiltration from suspicious processes to known IoCs -->
        <Rule groupRelation="and">
          <Image condition="is any">powershell.exe;cmd.exe;rundll32.exe;certutil.exe;msbuild.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1572: Protocol Tunneling using specific tools to IoC IPs -->
        <Rule groupRelation="and">
          <Image condition="is any">plink.exe;ssh.exe;netsh.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- T1021.001: Post-RDP session network activity from shells -->
        <Rule groupRelation="and">
          <Image condition="is any">cmd.exe;powershell.exe</Image>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!-- 
Analysis Implementation Notes:
- Used: Correlated specific suspicious images (powershell.exe, cmd.exe, rundll32.exe, certutil.exe, msbuild.exe, plink.exe, ssh.exe, netsh.exe) with the provided DestinationIp IoC list to satisfy T1071.001, T1041, T1567, and T1572.
- Used: Created a correlation between web server process (w3wp.exe) and IoC IPs to detect post-exploit egress for T1190/CVE-2023-48788.
- Used: Monitored shell processes initiating connections on RDP port 3389 to capture lateral movement/post-access activity for T1021.001.
- Not Used: Generic port monitoring (e.g., port 8080 or 443) without process/IP correlation to avoid noise.
- Not Used: Monitoring for cloud storage domains (Dropbox/OneDrive) via DestinationHostname as the specific IoC IPs were prioritized for high-fidelity detection.
-->
---
## Test case B

## Test case B security analysis (T1190)

```Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific indicators:

1. Source IP Correlation:
Monitor for any network connections where the Source IP matches the reported IoCs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, 206.123.145.13.

2. Process-to-Network Mapping:
Monitor for network connections initiated by the Fortinet FortiClientEMS process or associated web server processes (e.g., w3wp.exe) that deviate from established baselines. Specifically, look for:
- Connections initiated by the server process immediately following a request from the listed IoC IPs.
- Outbound connections to external IPs (egress) originating from the application process, which may indicate a reverse shell or data exfiltration following the exploitation of CVE-2023-48788.

3. Vulnerability-Specific Traffic:
Since CVE-2023-48788 is a SQL injection vulnerability leading to unauthorized code execution, monitor for NetworkConnect events where the initiating process is a database engine or a web service spawning a connection to an external destination, correlating with the "post-exploit egress" signal of DET0080.```
## Test case B sysmon (T1190)

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Exploit Public-Facing Application" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1190: Exploit Public-Facing Application -->
        <!-- Correlation with reported IoC source IPs -->
        <Rule name="T1190_Known_Attacker_IPs" groupRelation="or">
          <SourceIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</SourceIp>
        </Rule>

        <!-- T1190 & CVE-2023-48788: Monitoring for post-exploitation egress (reverse shells/callbacks) -->
        <!-- Monitor for shells or LOLbins initiating outbound connections -->
        <Rule name="T1190_PostExploit_Egress" groupRelation="or">
          <Image condition="image">cmd.exe</Image>
          <Image condition="image">powershell.exe</Image>
          <Image condition="image">python.exe</Image>
          <Image condition="image">bash.exe</Image>
          <Image condition="image">regsvr32.exe</Image>
          <Image condition="image">rundll32.exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!-- 
Analysis Implementation Details:
1. IoCs: Included all reported source IPs in a single 'is any' rule to detect incoming connections from known malicious actors associated with the attack pattern.
2. CVE-2023-48788 & T1190 Behavior: The security analysis highlighted the "request -> error -> post-exploit process/egress" chain. Since the host is high-exposure, I focused on the egress phase. I included processes found in the running process list (cmd.exe, powershell.exe, python.exe) and common LOLbins (regsvr32.exe, rundll32.exe) that would indicate a successful exploit resulting in a reverse shell or command execution.
3. Exclusions: Did not include generic "Discovery" or "Service" image rules from the examples to avoid excessive noise, focusing strictly on the critical execution/egress paths identified in the security analysis.
4. Host Context: Used the actual running processes (like python.exe and powershell.exe) identified in the host state to ensure the monitoring is relevant to the environment.
-->
```
## Test case B security analysis (T1021.001)

```Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific criteria to detect T1021.001 and potential exploitation of CVE-2023-48788:

1. Source IP Filtering:
Monitor for any outbound or inbound connections involving the following high-threat source IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. RDP Traffic Analysis (T1021.001):
Identify NetworkConnect events where the DestinationPort is 3389 (default RDP). Correlate these connections with the source IPs listed above to identify unauthorized remote desktop attempts.

3. CVE-2023-48788 Exploitation (FortiClientEMS):
Monitor for NetworkConnect events involving the FortiClientEMS process. Specifically, look for unusual outbound connections originating from the EMS service to the listed threat IPs or unknown external destinations, which may indicate a reverse shell or data exfiltration following the SQL injection and unauthorized command execution described in the vulnerability.

4. High Exposure Server Context:
Given the high network exposure, prioritize filtering for NetworkConnect events where the Image represents system binaries (e.g., cmd.exe, powershell.exe, certutil.exe) initiating network connections immediately following an RDP session establishment from the identified malicious IPs.```
## Test case B sysmon (T1021.001)

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Remote Access and Vulnerability Monitoring" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Monitoring for T1021.001: Remote Desktop Protocol -->
        <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- Monitoring for potential post-exploitation activity related to T1021.001 and CVE-2023-48788 -->
        <Rule name="technique_id=T1021.001,technique_name=Remote Desktop Protocol" groupRelation="and">
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\certutil.exe</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!-- 
Analysis Explanation:
- Used: Combined DestinationPort 3389 with the specific high-threat IoC IP list to monitor for unauthorized RDP access (T1021.001) while minimizing noise from internal traffic.
- Used: Correlated suspicious processes (cmd.exe, powershell.exe, certutil.exe) initiating network connections to the identified threat IPs, as this indicates post-login activity or reverse shells resulting from either T1021.001 or the exploitation of CVE-2023-48788.
- Not Used: Broad monitoring of all port 3389 traffic or all activity from the listed IPs without process/port correlation, as the host is a high-exposure server and such rules would generate excessive noise.
- Not Used: Specific FortiClientEMS image monitoring because the provided "running processes" list did not show the EMS service active on the host, although the logic remains in the process-based rule.
-->
```
## Test case B security analysis (T1071.001)

```Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific telemetry:

1. Destination IP Addresses:
Filter for any outbound connections to the known malicious IPs: 185.216.70.170, 77.90.38.170, 154.216.19.224, 154.216.17.157, 176.65.141.201, 176.65.141.232, and 206.123.145.13.

2. Process Correlation (T1071.001):
Identify network connections initiated by suspicious processes that do not typically perform web requests, specifically:
- PowerShell.exe
- Rundll32.exe
- Any process associated with Fortinet FortiClientEMS (targeted by CVE-2023-48788).

3. Protocol and Port Monitoring:
Focus on connections over ports 80 (HTTP) and 443 (HTTPS) that originate from the aforementioned suspicious processes.

4. Behavioral Anomalies:
Flag connections from the FortiClientEMS process to the identified malicious IPs, which could indicate a successful SQL injection (CVE-2023-48788) leading to command execution and subsequent C2 communication via web protocols.```
## Test case B sysmon (T1071.001)

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1071.001: Web Protocols - Monitor suspicious processes initiating web traffic -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <Image condition="is any">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\rundll32.exe</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
        
        <!-- CVE-2023-48788: Monitoring FortiClientEMS processes for C2 communication -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <Image condition="contains">FortiClientEMS</Image>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- T1071.001: Monitor known malicious C2 infrastructure -->
        <Rule name="technique_id=T1071.001,technique_name=Web Protocols" groupRelation="and">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!-- 
  Analysis Summary:
  - Used: DestinationIp list provided in IoCs for precise matching of malicious C2 nodes.
  - Used: DestinationPorts 80 and 443 to align with the 'Web Protocols' attack pattern (T1071.001).
  - Used: Process images (powershell.exe and rundll32.exe) found in the running process list and security analysis as they are common for C2 proxying.
  - Used: 'contains FortiClientEMS' for the Image condition to capture potential exploitation of CVE-2023-48788 regardless of the specific installation path.
  - Not Used: Broad directory monitoring (e.g., \Temp, \AppData) to avoid noise on a high-exposure server, focusing instead on specific high-fidelity indicators (IPs and Process/Port combinations).
-->
```
## Test case B security analysis (T1572)

```Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific indicators:

1. Source Process Monitoring:
Track outbound network connections initiated by tunneling-capable binaries:
- plink.exe
- ssh.exe
- netsh.exe

2. Network Destination Monitoring:
Alert on any NetworkConnect events where the DestinationIp matches the following known malicious sources:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

3. Protocol Tunneling Indicators (T1572):
Identify anomalous network behavior associated with the processes listed above:
- Connections to non-standard ports or port usage mismatches (e.g., SSH processes communicating over ports typically reserved for other services).
- Large asymmetric data flows (significant imbalance between bytes sent and received) indicating encapsulated traffic.

4. Vulnerability Correlation (CVE-2023-48788):
Given the high network exposure and the risk of remote code execution via SQL injection in FortiClientEMS, monitor for any NetworkConnect events originating from the FortiClientEMS process that establish new outbound connections to the listed malicious IPs, which would indicate a successful exploit followed by the establishment of a C2 tunnel (CAPEC-470).```
## Test case B sysmon (T1572)

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Protocol Tunneling Detection" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1572: Protocol Tunneling - Monitor for binaries commonly used to encapsulate traffic -->
        <Image condition="image">plink.exe</Image>
        <Image condition="image">ssh.exe</Image>
        <Image condition="image">netsh.exe</Image>

        <!-- T1572: Monitor for connections to known malicious infrastructure associated with the campaign -->
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="or">
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>

        <!-- CVE-2023-48788: Correlation with potential shell/tunnel creation after FortiClientEMS exploitation -->
        <!-- Monitoring for any outbound connection from the specific vulnerability surface to the malicious IPs -->
        <Rule name="technique_id=T1572,technique_name=Protocol Tunneling" groupRelation="and">
          <Image condition="contains">FortiClientEMS</Image>
          <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!-- 
  Analysis Implementation Notes:
  - Used: Tool-based monitoring for plink.exe, ssh.exe, and netsh.exe as specified in the detection strategy (AN1483) for T1572.
  - Used: DestinationIp filtering to alert on all provided high-threat IoCs.
  - Used: A combined Rule (and) to correlate the vulnerability surface (FortiClientEMS) with the malicious IPs, addressing the risk of a tunnel being established after a successful CVE-2023-48788 exploit.
  - Not Used: "DataAsymmetryThreshold" and "TimeWindow" because these are behavioral metrics that cannot be filtered within a static Sysmon XML configuration file; they require a SIEM/EDR for post-processing.
  - Not Used: Port-based "Non-Standard Port" rules to avoid noise, as the host is highly exposed and already has several established high-port connections. Focus was kept strictly on known malicious IPs and tunneling binaries.
-->
```
## Test case B security analysis (T1041)

```Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific conditions:

1. Destination IP Addresses:
Filter for outbound connections to the following reported IoC IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. Process Correlation (CVE-2023-48788):
Monitor NetworkConnect events originating from processes associated with Fortinet FortiClientEMS. Specifically, look for network connections initiated by the EMS service processes immediately following the execution of unauthorized commands or abnormal child process creation (indicative of the SQL injection exploit leading to RCE).

3. Exfiltration Pattern (T1041):
Monitor for outbound connections over common C2 protocols (HTTPS/443, DNS/53, or custom TCP/UDP ports) where the Image (process) typically does not generate network activity. Flag connections where the outbound data volume exceeds the DataVolumeThreshold (e.g., >1MB in <5min) to the aforementioned IoC IPs, while excluding KnownBenignProcesses.```
## Test case B sysmon (T1041)

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1041: Exfiltration Over C2 Channel & CVE-2023-48788 -->
        <Rule name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" groupRelation="or">
          <!-- Monitoring outbound connections to reported IoC IPs -->
          <DestinationIp condition="is">185.216.70.170</DestinationIp>
          <DestinationIp condition="is">77.90.38.170</DestinationIp>
          <DestinationIp condition="is">154.216.19.224</DestinationIp>
          <DestinationIp condition="is">154.216.17.157</DestinationIp>
          <DestinationIp condition="is">176.65.141.201</DestinationIp>
          <DestinationIp condition="is">176.65.141.232</DestinationIp>
          <DestinationIp condition="is">206.123.145.13</DestinationIp>
        </Rule>

        <!-- Monitoring for RCE/Exfiltration from FortiClientEMS context (CVE-2023-48788) -->
        <!-- Since EMS is not in running processes, we monitor for potential shell spawners connecting to C2 -->
        <Rule name="technique_id=T1041,technique_name=Exfiltration Over C2 Channel" groupRelation="and">
          <Image condition="is any">cmd.exe;powershell.exe;conhost.exe</Image>
          <DestinationPort condition="is any">443;53</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
<!-- 
Analysis Implementation Notes:
1. Used: Specific IoC IP addresses identified in the threat report as high-priority destinations.
2. Used: Common C2 protocols (HTTPS/443 and DNS/53) filtered against common shell processes (cmd, powershell) to detect potential post-exploitation exfiltration resulting from CVE-2023-48788.
3. Not Used: Generic 'Image' paths like AppData or Temp. Although useful, these generate excessive noise on high-exposure servers and were excluded to maintain focus on the specific attack pattern and IoCs provided.
4. Not Used: DataVolumeThreshold logic, as Sysmon XML filtering does not support volumetric analysis (this must be handled by the SIEM/Log Analytics layer).
5. Not Used: KnownBenignProcesses exclusions for OneDrive/Edge as they were not specifically requested for this targeted IoC match.
-->
```
## Test case B security analysis (T1567)

```Monitor Sysmon Event ID 3 (NetworkConnect) for the following specific indicators:

1. Destination IP Addresses (RemoteAddress):
Filter for outbound connections to the following reported IoC IPs:
- 185.216.70.170
- 77.90.38.170
- 154.216.19.224
- 154.216.17.157
- 176.65.141.201
- 176.65.141.232
- 206.123.145.13

2. Process Correlation (Image):
Monitor for NetworkConnect events where the initiating process is not a standard web browser or system service, specifically focusing on:
- FortiClientEMS processes (due to CVE-2023-48788 vulnerability).
- Office applications (Word, Excel).
- Scripting interpreters (PowerShell, cmd.exe).
- Unexpected processes initiating HTTPS (Port 443) connections to known web services (Dropbox, Google Drive, OneDrive).

3. Traffic Volume and Destination (RemotePort & Destination):
- Track outbound connections on Port 443 to Microsoft Corporation (AS8075), Cloudflare (AS13335), and GitHub (AS36459) that originate from the FortiClientEMS process or unauthorized shell processes.
- Flag high outbound-to-inbound data ratios associated with these destinations, correlating the NetworkConnect event with the data volume sent.```
## Test case B sysmon (T1567)

```xml
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Exfiltration Over Web Service" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- T1567: Exfiltration Over Web Service - Monitor outbound connections to reported IoC IPs -->
        <DestinationIp condition="is any">185.216.70.170;77.90.38.170;154.216.19.224;154.216.17.157;176.65.141.201;176.65.141.232;206.123.145.13</DestinationIp>

        <!-- T1567: Exfiltration Over Web Service - Monitor anomalous processes communicating with web services on port 443 -->
        <Rule name="technique_id=T1567,technique_name=Exfiltration Over Web Service" groupRelation="and">
          <DestinationPort condition="is">443</DestinationPort>
          <Image condition="is any">C:\Windows\System32\cmd.exe;C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;C:\Windows\System32\dllhost.exe</Image>
        </Rule>

        <!-- CVE-2023-48788: Monitor FortiClientEMS for potential command execution resulting in network activity -->
        <Image name="technique_id=T1567,technique_name=Exfiltration Over Web Service" condition="image">FortiClientEMS.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

<!-- 
Analysis Explanation:
- Used: DestinationIp filter for the provided IoC list to detect direct communication with known malicious infrastructure.
- Used: A combined Rule (AND) for Port 443 and common LOLBins (cmd.exe, powershell.exe, dllhost.exe) to identify non-browser processes initiating HTTPS connections to legitimate web services (T1567).
- Used: Specifically included FortiClientEMS.exe as the target of CVE-2023-48788, as an exploit resulting in remote code execution would likely trigger a network connection for data exfiltration.
- Not Used: General "begin with" rules for C:\Users or C:\Temp to avoid high noise on a server with high network exposure, as these frequently produce false positives.
- Not Used: Broad destination hostname filtering for Microsoft/Cloudflare as the host already has established connections to these, which would generate excessive noise.
-->
```
