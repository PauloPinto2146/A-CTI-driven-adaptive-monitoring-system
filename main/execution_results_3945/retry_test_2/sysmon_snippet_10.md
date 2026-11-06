<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <SourceImage condition="contains">wiseman.EXE</SourceImage>
      </ProcessAccess>

      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="end with">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400;0x001F0FFF</GrantedAccess>
        </Rule>
      </ProcessAccess>

      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="end with">winlogon.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>