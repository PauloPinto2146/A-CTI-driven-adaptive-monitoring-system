<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="include">
				<Image condition="is">wiseman.EXE</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is">rundll32.exe</Image>
			</DnsQuery>
			<DnsQuery onmatch="include">
				<Image condition="is any">PowerShell.exe;python.exe;rundll32.exe</Image>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>