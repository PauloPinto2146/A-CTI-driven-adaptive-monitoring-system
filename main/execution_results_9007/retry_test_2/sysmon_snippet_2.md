<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreateTime onmatch="include">
        <TargetFilename condition="end with">x86_64-unknown-linux-esxi.elf</TargetFilename>
        <TargetFilename condition="end with">h3odp7l2u.exe</TargetFilename>
        <TargetFilename condition="end with">hi9lezv.exe</TargetFilename>
        <TargetFilename condition="end with">072wiof7.exe</TargetFilename>
        <TargetFilename condition="end with">k0d649u.exe</TargetFilename>
        <TargetFilename condition="end with">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
        <TargetFilename condition="end with">2qfguc.exe</TargetFilename>
        <TargetFilename condition="end with">7hhel.exe</TargetFilename>
        <TargetFilename condition="end with">3ctjhm3.exe</TargetFilename>
        <TargetFilename condition="end with">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
        <TargetFilename condition="end with">bjiw49.exe</TargetFilename>
        <TargetFilename condition="end with">7l73h.exe</TargetFilename>
        <TargetFilename condition="end with">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
        <TargetFilename condition="end with">0m6m882x2.exe</TargetFilename>
        <TargetFilename condition="end with">inc.exe</TargetFilename>
        <TargetFilename condition="end with">61pd6n3t.exe</TargetFilename>
        <TargetFilename condition="end with">mk1yd.exe</TargetFilename>
        <TargetFilename condition="end with">a3mnw9.exe</TargetFilename>
        <TargetFilename condition="end with">win.bin</TargetFilename>
        <TargetFilename condition="end with">vw06lg0y.exe</TargetFilename>
        <TargetFilename condition="end with">qgp2s6z.exe</TargetFilename>
        <TargetFilename condition="end with">tt24n8xsl.exe</TargetFilename>
        <!-- Behavioral monitoring for generic executable and binary files used in ransomware/timestomp -->
        <TargetFilename condition="end with">.exe</TargetFilename>
        <TargetFilename condition="end with">.elf</TargetFilename>
        <TargetFilename condition="end with">.bin</TargetFilename>
      </FileCreateTime>
    </RuleGroup>
  </EventFiltering>
</Sysmon>