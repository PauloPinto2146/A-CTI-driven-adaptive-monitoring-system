
<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Credential dumping / token manipulation: access to LSASS -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\System32\lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
        </Rule>

        <!-- Keylogging / hooking: access to Winlogon or OSK with hooking APIs -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\System32\winlogon.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
          <CallTrace condition="contains any">advapi32.dll!OpenProcess;ntdll.dll!NtOpenProcess</CallTrace>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\System32\osk.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
          <CallTrace condition="contains any">advapi32.dll!OpenProcess;ntdll.dll!NtOpenProcess</CallTrace>
        </Rule>

        <!-- IOC: suspicious source executable wiseman.EXE opening any process with high‑privilege access -->
        <Rule groupRelation="and">
          <SourceImage condition="image">wiseman.EXE</SourceImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
