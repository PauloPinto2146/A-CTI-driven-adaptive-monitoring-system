<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <!-- IOC: malicious files observed as loaded modules -->
        <Rule groupRelation="or">
          <ImageLoaded condition="is any">x86_64-unknown-linux-esxi.elf;h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;win.bin;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</ImageLoaded>
        </Rule>
        <!-- BEHAVIOR: exploitation of public‑facing application (T1190) – unsigned module loaded into IIS worker process -->
        <Rule groupRelation="and">
          <Image condition="is">C:\Windows\System32\w3wp.exe</Image>
          <Signed condition="is">false</Signed>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>