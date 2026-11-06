<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Credential dumping: LSASS access with read/query or full access -->
        <Rule groupRelation="and">
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x0010;0x0400;0x1F0FFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
        </Rule>

        <!-- Packing/obfuscation: typical loaders creating threads / writing memory -->
        <Rule groupRelation="and">
          <SourceImage condition="image">rundll32.exe;powershell.exe</SourceImage>
          <GrantedAccess condition="contains any">0x0002;0x0020</GrantedAccess>
        </Rule>

        <!-- Known malicious executables -->
        <Rule groupRelation="and">
          <TargetImage condition="is any">h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;win.bin;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</TargetImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>