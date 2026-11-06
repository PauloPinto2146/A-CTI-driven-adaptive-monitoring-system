<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="include">
        <Image condition="is any">wiseman.exe;rundll32.exe;powershell.exe;python.exe;mstsc.exe;ssh.exe;net.exe;ping.exe</Image>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>