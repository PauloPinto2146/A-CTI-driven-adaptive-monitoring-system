<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Indicator: wiseman.exe as source -->
        <Rule groupRelation="and">
          <SourceImage condition="contains">wiseman.exe</SourceImage>
        </Rule>

        <!-- Behavior T1134 – access to LSASS with read‑type rights -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400</GrantedAccess>
          <CallTrace condition="contains">advapi32.dll</CallTrace>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400</GrantedAccess>
          <CallTrace condition="contains">kernel32.dll</CallTrace>
        </Rule>

        <!-- Behavior T1056.001 – keylogging‑related process access to winlogon.exe or osk.exe with high‑privilege rights -->
        <Rule groupRelation="and">
          <TargetImage condition="is any">C:\Windows\System32\winlogon.exe;C:\Windows\System32\osk.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1F0FFF;0x0010;0x0400</GrantedAccess>
          <CallTrace condition="contains">user32.dll</CallTrace>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="is any">C:\Windows\System32\winlogon.exe;C:\Windows\System32\osk.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1F0FFF;0x0010;0x0400</GrantedAccess>
          <CallTrace condition="contains">kernel32.dll</CallTrace>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>