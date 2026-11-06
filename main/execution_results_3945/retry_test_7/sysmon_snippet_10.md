<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Credential dumping via LSASS access -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0418;0x0010;0x0400;0x0008</GrantedAccess>
          <CallTrace condition="contains">kernel32.dll!OpenProcess</CallTrace>
        </Rule>

        <!-- Keylogging hook installation on winlogon.exe -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\winlogon.exe</TargetImage>
          <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
          <CallTrace condition="contains">user32.dll!SetWindowsHookEx</CallTrace>
        </Rule>

        <!-- Keylogging hook installation on osk.exe -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\osk.exe</TargetImage>
          <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
          <CallTrace condition="contains">user32.dll!SetWindowsHookEx</CallTrace>
        </Rule>

        <!-- Token manipulation (duplicate/assign primary) -->
        <Rule groupRelation="and">
          <GrantedAccess condition="contains any">0x0001;0x0002;0x0080</GrantedAccess>
          <CallTrace condition="contains">advapi32.dll!DuplicateTokenEx</CallTrace>
        </Rule>

        <!-- IOC: suspicious source process named wiseman.EXE -->
        <Rule groupRelation="and">
          <SourceImage condition="contains">wiseman.EXE</SourceImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>