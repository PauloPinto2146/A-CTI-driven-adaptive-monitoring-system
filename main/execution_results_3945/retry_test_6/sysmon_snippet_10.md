<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: specific malicious source executable -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <SourceImage condition="image">wiseman.EXE</SourceImage>
        </Rule>
      </ProcessAccess>

      <!-- BEHAVIOR: keylogging / API‑hook injection targeting winlogon or osk with high‑privilege process rights -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <TargetImage condition="is any">C:\Windows\system32\winlogon.exe;C:\Windows\system32\osk.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0020;0x0080</GrantedAccess>
        </Rule>
      </ProcessAccess>

      <!-- BEHAVIOR: token manipulation – suspicious token‑related access rights -->
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <GrantedAccess condition="contains any">0x0002;0x0004;0x0020</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>