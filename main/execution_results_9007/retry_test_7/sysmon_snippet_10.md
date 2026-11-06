<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <!-- IOC rules for each observed malicious executable opening LSASS -->
        <Rule groupRelation="and">
          <SourceImage condition="is">x86_64-unknown-linux-esxi.elf</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">h3odp7l2u.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">hi9lezv.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">072wiof7.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">k0d649u.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2qfguc.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">7hhel.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">3ctjhm3.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">bjiw49.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">7l73h.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">0m6m882x2.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">inc.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">61pd6n3t.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">mk1yd.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">a3mnw9.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">win.bin</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">vw06lg0y.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">qgp2s6z.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="is">tt24n8xsl.exe</SourceImage>
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>

        <!-- BEHAVIOR rule: any process opening LSASS with typical credential‑dumping access rights -->
        <Rule groupRelation="and">
          <TargetImage condition="is">lsass.exe</TargetImage>
          <GrantedAccess condition="contains any">0x1F0FFF;0x1F1FFF;0x1FFFFF;0x143A;0x1010</GrantedAccess>
        </Rule>

        <!-- DERIVED rule: processes opening another process with rights that enable in‑memory unpacking / injection (PROCESS_CREATE_THREAD + PROCESS_VM_WRITE) -->
        <Rule groupRelation="and">
          <GrantedAccess condition="contains any">0x2;0x20</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>