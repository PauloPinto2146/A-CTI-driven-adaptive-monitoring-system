<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- IOC: malicious binaries reading LSASS -->
        <Rule groupRelation="and">
          <SourceImage condition="is any">h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x0410</GrantedAccess>
        </Rule>
        <!-- BEHAVIOR: non‑system process injecting into common Windows services (unpacking / code‑injection) -->
        <Rule groupRelation="and">
          <SourceImage condition="not begin with">C:\Windows\System32\</SourceImage>
          <SourceImage condition="not begin with">C:\Windows\SysWOW64\</SourceImage>
          <TargetImage condition="is any">svchost.exe;explorer.exe;services.exe</TargetImage>
          <GrantedAccess condition="is">0x0022</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>