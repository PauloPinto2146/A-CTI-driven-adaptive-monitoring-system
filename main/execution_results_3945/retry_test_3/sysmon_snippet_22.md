<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="include">
        <Image condition="contains">wiseman.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="contains">rundll32.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="is any">powershell.exe;python.exe;rundll32.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="contains">rundll32.exe</Image>
        <QueryStatus condition="is not">0</QueryStatus>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="contains">wiseman.exe</Image>
        <QueryStatus condition="is not">0</QueryStatus>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>