<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="Suspicious DNS Queries" groupRelation="or">
      <DnsQuery onmatch="include">
        <Image condition="contains">wiseman.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="contains">rundll32.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="contains">powershell.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="contains">python.exe</Image>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>