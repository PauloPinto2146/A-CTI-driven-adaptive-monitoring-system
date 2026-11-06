<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: wiseman.exe -->
        <Rule groupRelation="and">
          <Image condition="end with">wiseman.exe</Image>
        </Rule>

        <!-- BEHAVIOR: Rundll32 abuse for DNS tunneling -->
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <DestinationPort condition="is">53</DestinationPort>
          <Protocol condition="is">udp</Protocol>
        </Rule>

        <!-- BEHAVIOR: Remote Services (RDP, SSH, SMB) -->
        <Rule groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
          <Initiated condition="is">true</Initiated>
          <Image condition="excludes any">svchost.exe;lsass.exe;services.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationPort condition="is">22</DestinationPort>
          <Initiated condition="is">true</Initiated>
          <Image condition="excludes any">svchost.exe;lsass.exe;services.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <DestinationPort condition="is">445</DestinationPort>
          <Initiated condition="is">true</Initiated>
          <Image condition="excludes any">svchost.exe;lsass.exe;services.exe</Image>
        </Rule>

        <!-- BEHAVIOR: Remote System Discovery utilities -->
        <Rule groupRelation="and">
          <Image condition="end with">net.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">ping.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">tracert.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Dead‑Drop Resolver (pastebin, twitter) -->
        <Rule groupRelation="and">
          <DestinationHostname condition="is">pastebin.com</DestinationHostname>
        </Rule>
        <Rule groupRelation="and">
          <DestinationHostname condition="is">twitter.com</DestinationHostname>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>