<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- IOC – specific malicious binaries opening LSASS -->
        <Rule groupRelation="and">
          <SourceImage condition="image">x86_64-unknown-linux-esxi.elf</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">h3odp7l2u.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">hi9lezv.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">072wiof7.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">k0d649u.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2qfguc.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">7hhel.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">3ctjhm3.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">bjiw49.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">7l73h.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">0m6m882x2.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">inc.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">61pd6n3t.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">mk1yd.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">a3mnw9.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">win.bin</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">vw06lg0y.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">qgp2s6z.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">tt24n8xsl.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>

        <!-- BEHAVIOR – any process attempting full access to LSASS (T1003) -->
        <Rule groupRelation="and">
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess>0x1F0FFF</GrantedAccess>
        </Rule>

        <!-- BEHAVIOR – process creation thread indicative of unpacking/loaders (T1027.002) -->
        <Rule groupRelation="and">
          <GrantedAccess>0x0002</GrantedAccess>
          <CallTrace condition="contains any">C:\Windows\System32\ntdll.dll;C:\Windows\System32\kernelbase.dll</CallTrace>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>