
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: wiseman.exe network activity -->
        <Rule groupRelation="and">
          <Image condition="image">wiseman.exe</Image>
        </Rule>

        <!-- BEHAVIOR: rundll32.exe usage -->
        <Rule groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
        </Rule>

        <!-- BEHAVIOR: DNS tunneling via UDP/53 from suspicious scripts -->
        <Rule groupRelation="and">
          <Image condition="is any">powershell.exe;rundll32.exe;python.exe</Image>
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Remote Services – RDP -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Remote Services – SSH -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">22</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Remote Services – VNC -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">5900</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Remote System Discovery – SMB (445) from enumeration tools -->
        <Rule groupRelation="and">
          <Image condition="is any">net.exe;ping.exe;tracert.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
