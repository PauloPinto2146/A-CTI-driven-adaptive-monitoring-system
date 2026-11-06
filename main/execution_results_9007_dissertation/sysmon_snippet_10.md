<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- Credential dumping: access to LSASS -->
        <Rule groupRelation="and">
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1FFFFF;0x1F1FFF;0x1010;0x143A</GrantedAccess>
        </Rule>

        <!-- Potential packing/unpacking: process creates thread in another process -->
        <Rule groupRelation="and">
          <GrantedAccess condition="contains">0x0002</GrantedAccess>
        </Rule>

        <!-- Indicators of compromise: known malicious executables as source processes -->
        <Rule groupRelation="and">
          <SourceImage condition="image">x86_64-unknown-linux-esxi.elf</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">h3odp7l2u.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">hi9lezv.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">072wiof7.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">k0d649u.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akai_cobalt-strike_glassworm_poet-rat</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2qfguc.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">7hhel.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">3ctjhm3.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akai_cobalt-strike_glassworm_poet-rat</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">bjiw49.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">7l73h.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akai_cobalt-strike_glassworm_poet-rat</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">0m6m882x2.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">inc.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">61pd6n3t.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">mk1yd.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">a3mnw9.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">win.bin</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">vw06lg0y.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">qgp2s6z.exe</SourceImage>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">tt24n8xsl.exe</SourceImage>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>