<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <SourceImage condition="image">wiseman.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="image">winlogon.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0040;0x0080</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>