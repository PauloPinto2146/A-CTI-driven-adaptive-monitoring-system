<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Credential dumping: access to LSASS with full rights -->
        <Rule groupRelation="and">
          <TargetImage condition="is">C:\Windows\system32\lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>

        <!-- Process injection / unpacking behavior: suspicious high‑privilege access flags -->
        <Rule groupRelation="and">
          <GrantedAccess condition="contains any">0x1F0FFF;0x1F1FFF;0x143A;0x1410;0x1010;0x1F2FFF;0x1F3FFF;0x1FFFFF;0x147A;0x1028</GrantedAccess>
        </Rule>

        <!-- IOC: known malicious executables acting as source processes -->
        <Rule groupRelation="and">
          <SourceImage condition="is">x86_64-unknown-linux-esxi.elf</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">h3odp7l2u.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">hi9lezv.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">072wiof7.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">k0d649u.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2qfguc.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">7hhel.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">3ctjhm3.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">bjiw49.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">7l73h.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">0m6m882x2.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">inc.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">61pd6n3t.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">mk1yd.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">a3mnw9.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">win.bin</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">vw06lg0y.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">qgp2s6z.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">tt24n8xsl.exe</SourceImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>