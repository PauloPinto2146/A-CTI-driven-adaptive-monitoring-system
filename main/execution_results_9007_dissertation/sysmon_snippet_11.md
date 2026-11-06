<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <!-- IOC file names -->
        <TargetFilename condition="is">x86_64-unknown-linux-esxi.elf</TargetFilename>
        <TargetFilename condition="is">h3odp7l2u.exe</TargetFilename>
        <TargetFilename condition="is">hi9lezv.exe</TargetFilename>
        <TargetFilename condition="is">072wiof7.exe</TargetFilename>
        <TargetFilename condition="is">k0d649u.exe</TargetFilename>
        <TargetFilename condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
        <TargetFilename condition="is">2qfguc.exe</TargetFilename>
        <TargetFilename condition="is">7hhel.exe</TargetFilename>
        <TargetFilename condition="is">3ctjhm3.exe</TargetFilename>
        <TargetFilename condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
        <TargetFilename condition="is">bjiw49.exe</TargetFilename>
        <TargetFilename condition="is">7l73h.exe</TargetFilename>
        <TargetFilename condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</TargetFilename>
        <TargetFilename condition="is">0m6m882x2.exe</TargetFilename>
        <TargetFilename condition="is">inc.exe</TargetFilename>
        <TargetFilename condition="is">61pd6n3t.exe</TargetFilename>
        <TargetFilename condition="is">mk1yd.exe</TargetFilename>
        <TargetFilename condition="is">a3mnw9.exe</TargetFilename>
        <TargetFilename condition="is">win.bin</TargetFilename>
        <TargetFilename condition="is">vw06lg0y.exe</TargetFilename>
        <TargetFilename condition="is">qgp2s6z.exe</TargetFilename>
        <TargetFilename condition="is">tt24n8xsl.exe</TargetFilename>

        <!-- Behavior: Exfiltration Over Web Service – files dropped in common user folders -->
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\Downloads\</TargetFilename>
          <TargetFilename condition="end with">.exe</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\Downloads\</TargetFilename>
          <TargetFilename condition="end with">.elf</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\Temp\</TargetFilename>
          <TargetFilename condition="end with">.exe</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\Temp\</TargetFilename>
          <TargetFilename condition="end with">.dll</TargetFilename>
        </Rule>

        <!-- Behavior: Remote Access Tools – persistence via Startup folder -->
        <Rule groupRelation="and">
          <TargetFilename condition="contains">\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\</TargetFilename>
          <TargetFilename condition="end with">.exe</TargetFilename>
        </Rule>

        <!-- Derived: Potential exploitation of system binaries (CVE‑2023‑3519) -->
        <Rule groupRelation="and">
          <TargetFilename condition="begin with">C:\Windows\System32\</TargetFilename>
          <TargetFilename condition="end with">.exe</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="begin with">C:\Windows\System32\</TargetFilename>
          <TargetFilename condition="end with">.dll</TargetFilename>
        </Rule>

        <!-- Derived: Ransomware file‑encryption artifacts (T1486) -->
        <TargetFilename condition="end with">.txt</TargetFilename>
        <TargetFilename condition="end with">.lock</TargetFilename>
        <TargetFilename condition="end with">.encrypted</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>