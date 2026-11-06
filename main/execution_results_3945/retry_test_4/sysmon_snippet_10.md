<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- IOC: specific malicious source executable -->
        <Rule groupRelation="and">
          <SourceImage condition="image">wiseman.exe</SourceImage>
        </Rule>

        <!-- BEHAVIOR: non‑UI service accessing winlogon for credential capture (T1056.001) -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\winlogon.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0020;0x0080</GrantedAccess>
        </Rule>

        <!-- BEHAVIOR: non‑UI service accessing osk.exe for credential capture (T1056.001) -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\osk.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0020;0x0080</GrantedAccess>
        </Rule>

        <!-- BEHAVIOR: any process reading LSASS for token manipulation (T1134) -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400</GrantedAccess>
        </Rule>

        <!-- DERIVED: post‑exploit full‑access to LSASS after CVE‑2023‑27350 -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>