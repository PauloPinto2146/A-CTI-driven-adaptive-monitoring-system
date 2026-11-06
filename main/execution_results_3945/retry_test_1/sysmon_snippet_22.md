<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="Suspicious DNS queries" groupRelation="or">
			<DnsQuery onmatch="include">
				<Image condition="is">wiseman.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is">rundll32.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is">powershell.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is">python.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is any">net.exe;ping.exe;tracert.exe</Image>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>