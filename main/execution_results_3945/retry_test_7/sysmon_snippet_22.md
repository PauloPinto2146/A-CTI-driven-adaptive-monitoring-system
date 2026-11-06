<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="include">
				<Image condition="image">wiseman.EXE</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="image">rundll32.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<QueryName condition="is any">pastebin.com;twitter.com</QueryName>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>