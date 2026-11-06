<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: malicious process “wiseman.EXE” opening any other process -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <SourceImage condition="image">wiseman.EXE</SourceImage>
        </Rule>
      </ProcessAccess>

      <!-- BEHAVIOR: any process accessing LSASS (T1134 – Access Token Manipulation / Credential Dumping) -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="image">lsass.exe</TargetImage>
        </Rule>
      </ProcessAccess>

      <!-- BEHAVIOR: any process accessing WINLOGON (T1056.001 – Keylogging) -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="image">winlogon.exe</TargetImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>