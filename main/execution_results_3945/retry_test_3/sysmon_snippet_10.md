<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- IOC: wiseman.exe accessing LSASS -->
        <Rule groupRelation="and">
          <SourceImage condition="contains">wiseman.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
          <CallTrace condition="contains any">ntdll!ZwOpenProcess;advapi32!OpenProcessToken</CallTrace>
        </Rule>

        <!-- BEHAVIOR: Token‑manipulation activity targeting LSASS (T1134) -->
        <Rule groupRelation="and">
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
          <CallTrace condition="contains any">ntdll!ZwOpenProcess;advapi32!OpenProcessToken;kernel32!CreateProcessAsUser;ntdll!ZwDuplicateToken</CallTrace>
        </Rule>

        <!-- BEHAVIOR: Hooking of winlogon.exe for keylogging (T1056.001) -->
        <Rule groupRelation="and">
          <TargetImage condition="image">winlogon.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1010</GrantedAccess>
          <CallTrace condition="contains any">user32!SetWindowsHookExW;user32!SetWindowsHookExA</CallTrace>
        </Rule>

        <!-- BEHAVIOR: Hooking of osk.exe for keylogging (T1056.001) -->
        <Rule groupRelation="and">
          <TargetImage condition="image">osk.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1010</GrantedAccess>
          <CallTrace condition="contains any">user32!SetWindowsHookExW;user32!SetWindowsHookExA</CallTrace>
        </Rule>

        <!-- BEHAVIOR: Use of built‑in decoding tools (T1140) -->
        <Rule groupRelation="and">
          <SourceImage condition="contains any">certutil.exe;powershell.exe;copy.exe</SourceImage>
          <TargetImage condition="contains any">cmd.exe;powershell.exe;certutil.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1010</GrantedAccess>
          <CallTrace condition="contains any">kernel32!CreateProcessW;kernel32!CreateProcessAsUser</CallTrace>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>