<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: wiseman.exe -->
        <Image condition="image">wiseman.exe</Image>

        <!-- BEHAVIOR: Rundll32 abuse -->
        <Image condition="image">rundll32.exe</Image>

        <!-- BEHAVIOR: DNS tunneling (non‑browser UDP DNS) -->
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote Services – RDP -->
        <Rule groupRelation="and">
          <Image condition="image">mstsc.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote Services – SSH -->
        <Rule groupRelation="and">
          <Image condition="image">ssh.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">22</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote System Discovery – net.exe SMB -->
        <Rule groupRelation="and">
          <Image condition="image">net.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
        </Rule>

        <!-- DERIVED: Dead‑drop resolver web services -->
        <DestinationHostname condition="end with">pastebin.com</DestinationHostname>
        <DestinationHostname condition="end with">twitter.com</DestinationHostname>
        <DestinationHostname condition="end with">github.com</DestinationHostname>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>