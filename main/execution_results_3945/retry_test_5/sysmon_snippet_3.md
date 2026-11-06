<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: wiseman.exe -->
        <Rule groupRelation="and">
          <Image condition="image">wiseman.exe</Image>
        </Rule>

        <!-- BEHAVIOR: rundll32.exe proxy execution -->
        <Rule groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: UDP initiations excluding typical DNS clients -->
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <Initiated condition="is">true</Initiated>
          <Image condition="is not">svchost.exe</Image>
          <Image condition="is not">dns.exe</Image>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>