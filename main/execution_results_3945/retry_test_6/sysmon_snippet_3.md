<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="MaliciousActivity" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="image">wiseman.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image condition="image">wininet.dll</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image condition="image">rundll32.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Protocol condition="is">udp</Protocol>
        <DestinationPort condition="is">53</DestinationPort>
        <Initiated condition="is">true</Initiated>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Protocol condition="is">tcp</Protocol>
        <DestinationPort condition="is">3389</DestinationPort>
        <Initiated condition="is">true</Initiated>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Protocol condition="is">tcp</Protocol>
        <DestinationPort condition="is">22</DestinationPort>
        <Initiated condition="is">true</Initiated>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Protocol condition="is">tcp</Protocol>
        <DestinationPort condition="is">5900</DestinationPort>
        <Initiated condition="is">true</Initiated>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image condition="image">net.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image condition="image">ping.exe</Image>
      </NetworkConnect>
      <NetworkConnect onmatch="include">
        <Image condition="image">tracert.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>