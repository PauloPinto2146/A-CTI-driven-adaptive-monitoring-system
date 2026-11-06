<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: wiseman.exe -->
        <Image condition="image">wiseman.exe</Image>

        <!-- BEHAVIOR: Rundll32 usage -->
        <Image condition="image">rundll32.exe</Image>

        <!-- BEHAVIOR: DNS tunneling (UDP to port 53) -->
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote Services - RDP -->
        <DestinationPort condition="is">3389</DestinationPort>

        <!-- BEHAVIOR: Remote Services - SSH -->
        <DestinationPort condition="is">22</DestinationPort>

        <!-- BEHAVIOR: Remote System Discovery / SMB -->
        <DestinationPort condition="is">445</DestinationPort>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>