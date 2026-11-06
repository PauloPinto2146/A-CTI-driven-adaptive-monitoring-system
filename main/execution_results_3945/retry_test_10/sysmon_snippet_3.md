<?xml version="1.0" encoding="utf-8"?>
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: wiseman.exe -->
        <Rule groupRelation="and">
          <Image condition="image">wiseman.exe</Image>
        </Rule>

        <!-- BEHAVIOR: Rundll32 abuse (T1218.011) -->
        <Rule groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
        </Rule>

        <!-- BEHAVIOR: DNS tunneling over UDP (T1071.004) -->
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote Services – RDP (T1021) -->
        <Rule groupRelation="and">
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote Services – SSH (T1021) -->
        <Rule groupRelation="and">
          <DestinationPort condition="is">22</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Remote System Discovery via net.exe to SMB (T1018) -->
        <Rule groupRelation="and">
          <Image condition="image">net.exe</Image>
          <DestinationPort condition="is">445</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>