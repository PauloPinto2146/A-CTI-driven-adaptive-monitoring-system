<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="image">wiseman.exe</Image>
        <DestinationHostname condition="is">pastebin.com</DestinationHostname>
        <DestinationHostname condition="is">twitter.com</DestinationHostname>
        <Rule groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>