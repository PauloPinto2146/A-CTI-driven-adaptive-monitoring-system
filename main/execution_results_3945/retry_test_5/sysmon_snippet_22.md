<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="include">
				<Image condition="is">wiseman.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is">rundll32.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is any">powershell.exe;python.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is any">net.exe;ping.exe</Image>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>