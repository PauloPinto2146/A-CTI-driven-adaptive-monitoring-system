<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="include">
				<Image condition="end with">\rundll32.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="end with">wiseman.EXE</Image>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>