<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- IOC: wiseman.exe accessing LSASS -->
        <Rule groupRelation="and">
          <SourceImage condition="image">wiseman.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400;0x0040</GrantedAccess>
        </Rule>

        <!-- BEHAVIOR: Any process accessing high‑value system processes -->
        <Rule groupRelation="and">
          <TargetImage condition="is any">lsass.exe;winlogon.exe;services.exe;csrss.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1F0FFF;0x0010;0x0400;0x0040</GrantedAccess>
        </Rule>

        <!-- BEHAVIOR: Built‑in decoding tools spawning new executables -->
        <Rule groupRelation="and">
          <SourceImage condition="is any">certutil.exe;powershell.exe;copy.exe</SourceImage>
          <TargetImage condition="ends with">.exe</TargetImage>
          <GrantedAccess condition="contains">0x0080</GrantedAccess>
        </Rule>

        <!-- DERIVED: Post‑exploitation activity after CVE‑2023‑27350 exploitation -->
        <Rule groupRelation="and">
          <SourceImage condition="image">PaperCutNG.exe</SourceImage>
          <TargetImage condition="is any">svchost.exe;services.exe</TargetImage>
          <GrantedAccess condition="contains">0x1F0FFF</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>