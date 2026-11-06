
.Context:
	EventID 22: This event is generated when a process executes a DNS query, whether the result is successful or fails, cached or not. The telemetry for this event was added for Windows 8.1 so it is not available on Windows 7 and earlier.

	These are the applicable tags that you can use:
	QueryName: DNS name that was queried
QueryStatus: Query result status code
QueryResults: Results of the query
Image: File path of the process that made the DNS query

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
	<!-- special thanks to @SwiftOnSecurity for this -->
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="exclude">
				<QueryName condition="end with">.mozaws.net</QueryName>				<!--Mozilla-->
				<QueryName condition="end with">.mozilla.com</QueryName>				<!--Mozilla-->
				<QueryName condition="end with">.mozilla.net</QueryName>				<!--Mozilla-->
				<QueryName condition="end with">.mozilla.org</QueryName>				<!--Mozilla-->
				<QueryName condition="is">clients1.google.com</QueryName>				<!--Google-->
				<QueryName condition="is">clients2.google.com</QueryName>				<!--Google-->
				<QueryName condition="is">clients3.google.com</QueryName>				<!--Google-->
				<QueryName condition="is">clients4.google.com</QueryName>				<!--Google-->
				<QueryName condition="is">clients5.google.com</QueryName>				<!--Google-->
				<QueryName condition="is">clients6.google.com</QueryName>				<!--Google-->
				<QueryName condition="is">safebrowsing.googleapis.com</QueryName>				<!--Google-->
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<!-- special thanks to @SwiftOnSecurity for this -->
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="exclude">
				<QueryName condition="end with">-pushp.svc.ms</QueryName>				<!--Microsoft: Doesn't appear to host customer content or subdomains-->
				<QueryName condition="end with">.b-msedge.net</QueryName>				<!--Microsoft: Doesn't appear to host customer content or subdomains-->
				<QueryName condition="end with">.bing.com</QueryName>				<!-- Microsoft | Microsoft default exclusion -->
				<QueryName condition="end with">.hotmail.com</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.live.com</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.live.net</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.s-microsoft.com</QueryName>				<!--Microsoft-->
				<QueryName condition="end with">.microsoft.com</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.microsoftonline.com</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.microsoftstore.com</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.ms-acdc.office.com</QueryName>				<!--Microsoft: Doesn't appear to host customer content or subdomains-->
				<QueryName condition="end with">.msedge.net</QueryName>				<!--Microsoft: Doesn't appear to host customer content or subdomains-->
				<QueryName condition="end with">.msn.com</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.msocdn.com</QueryName>				<!--Microsoft-->
				<QueryName condition="end with">.skype.com</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.skype.net</QueryName>				<!--Microsoft | Microsoft default exclusion-->
				<QueryName condition="end with">.windows.com</QueryName>				<!--Microsoft-->
				<QueryName condition="end with">.windows.net.nsatc.net</QueryName>				<!--Microsoft-->
				<QueryName condition="end with">.windowsupdate.com</QueryName>				<!--Microsoft-->
				<QueryName condition="end with">.xboxlive.com</QueryName>				<!--Microsoft-->
				<QueryName condition="is">login.windows.net</QueryName>				<!--Microsoft-->
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

<example>
<Sysmon schemaversion="4.30">
	<!-- special thanks to @SwiftOnSecurity for this -->
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="exclude">
				<Image condition="contains all">C:\Windows\SystemApps\Microsoft.Windows.Search;SearchApp.exe</Image>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>
</example>

	Examples of rules that include suspicious activity:
	

.Instruction:
	The previous security analysis contains monitoring recommendations classified as [IOC], [BEHAVIOR], or [DERIVED].
	Your task is to translate those recommendations into valid Sysmon DnsQuery snippet of the sysmon configuration file.

.Requirements
	- Use exclude rules only for well-known benign noise, and never for anything that matches the indicators or techniques identified in the analysis.
	- DO NOT invent specific file paths, folder names, or hashes that were not explicitly given in the IoCs context or the security analysis. 
	- Be aware that the "Image" field in Sysmon is a full path or a single file and its extension.
	- Do NOT implement monitoring rules outside of the reported attack patterns: ['T1557', 'T1071', 'T1190', 'T1567', 'T1219', 'T1021.002', 'T1018', 'T1021.001', 'T1569.002']
	- Remember to consider the reported indicators of compromise: ['x86_64-unknown-linux-esxi.elf', 'h3odp7l2u.exe', 'hi9lezv.exe', '072wiof7.exe', 'k0d649u.exe', '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat', '2qfguc.exe', '7hhel.exe', '3ctjhm3.exe', '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat', 'bjiw49.exe', '7l73h.exe', '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat', '0m6m882x2.exe', 'inc.exe', '61pd6n3t.exe', 'mk1yd.exe', 'a3mnw9.exe', 'win.bin', 'vw06lg0y.exe', 'qgp2s6z.exe', 'tt24n8xsl.exe', 'incblog.su', 'incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion', 'incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion']
	- Use groupRelation="and" only when all child conditions describe a single monitoring requirement and must simultaneously be true
	- The event element (e.g., <RegistryEvent>) MUST contain only the "onmatch" attribute. NEVER add a "name" attribute to an event element.

ONLY output the xml.
	