<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DnsQuery onmatch="include">
        <QueryName condition="is">incblog.su</QueryName>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <QueryName condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</QueryName>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <QueryName condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</QueryName>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="is any">h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</Image>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>