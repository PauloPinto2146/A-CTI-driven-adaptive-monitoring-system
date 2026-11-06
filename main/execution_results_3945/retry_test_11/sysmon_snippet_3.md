<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: suspicious executable -->
        <Image condition="end with">wiseman.exe</Image>

        <!-- BEHAVIOR: rundll32.exe used for web or DNS -->
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: DNS tunneling (any process) -->
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote Services – RDP -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Remote Services – WMI/DCOM -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">135</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: Enumeration traffic (SMB/SSH) -->
        <DestinationPort condition="is any">445;139;22</DestinationPort>

        <!-- DERIVED: Dead‑Drop Resolver (pastebin or twitter) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">443</DestinationPort>
          <DestinationHostname condition="is any">pastebin.com;twitter.com</DestinationHostname>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>