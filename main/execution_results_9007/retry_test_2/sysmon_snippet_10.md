<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Credential dumping: access to LSASS with high‑privilege rights (T1003) -->
        <Rule groupRelation="and">
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1010</GrantedAccess>
        </Rule>

        <!-- Malicious binaries observed in the threat feed (T1027.002 / IoCs) -->
        <TargetImage condition="is">x86_64-unknown-linux-esxi.elf</TargetImage>
        <TargetImage condition="is">h3odp7l2u.exe</TargetImage>
        <TargetImage condition="is">hi9lezv.exe</TargetImage>
        <TargetImage condition="is">072wiof7.exe</TargetImage>
        <TargetImage condition="is">k0d649u.exe</TargetImage>
        <TargetImage condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</TargetImage>
        <TargetImage condition="is">2qfguc.exe</TargetImage>
        <TargetImage condition="is">7hhel.exe</TargetImage>
        <TargetImage condition="is">3ctjhm3.exe</TargetImage>
        <TargetImage condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</TargetImage>
        <TargetImage condition="is">bjiw49.exe</TargetImage>
        <TargetImage condition="is">7l73h.exe</TargetImage>
        <TargetImage condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</TargetImage>
        <TargetImage condition="is">0m6m882x2.exe</TargetImage>
        <TargetImage condition="is">inc.exe</TargetImage>
        <TargetImage condition="is">61pd6n3t.exe</TargetImage>
        <TargetImage condition="is">mk1yd.exe</TargetImage>
        <TargetImage condition="is">a3mnw9.exe</TargetImage>
        <TargetImage condition="is">win.bin</TargetImage>
        <TargetImage condition="is">vw06lg0y.exe</TargetImage>
        <TargetImage condition="is">qgp2s6z.exe</TargetImage>
        <TargetImage condition="is">tt24n8xsl.exe</TargetImage>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>