<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Suspicious DNS Queries" groupRelation="or">
      <DnsQuery onmatch="include">
        <Image condition="contains">wiseman.EXE</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="contains any">powershell.exe;python.exe;rundll32.exe</Image>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>