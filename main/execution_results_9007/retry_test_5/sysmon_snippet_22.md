<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="SuspiciousDnsQueries" groupRelation="or">
      <!-- IOC: specific malicious domains -->
      <DnsQuery onmatch="include">
        <QueryName condition="is">incblog.su</QueryName>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <QueryName condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</QueryName>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <QueryName condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</QueryName>
      </DnsQuery>

      <!-- BEHAVIOR: any .onion domain (Tor hidden services) -->
      <DnsQuery onmatch="include">
        <QueryName condition="end with">.onion</QueryName>
      </DnsQuery>

      <!-- BEHAVIOR: potential DNS poisoning / failed resolution (AiTM) -->
      <DnsQuery onmatch="include">
        <QueryStatus condition="is any">NXDOMAIN;SERVFAIL</QueryStatus>
      </DnsQuery>

      <!-- BEHAVIOR: internal discovery hostnames -->
      <DnsQuery onmatch="include">
        <QueryName condition="end with">.local</QueryName>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <QueryName condition="end with">.lan</QueryName>
      </DnsQuery>

      <!-- IOC: malicious executables performing DNS queries -->
      <DnsQuery onmatch="include">
        <Image condition="end with">x86_64-unknown-linux-esxi.elf</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">h3odp7l2u.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">hi9lezv.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">072wiof7.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">k0d649u.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">2qfguc.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">7hhel.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">3ctjhm3.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">bjiw49.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">7l73h.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">0m6m882x2.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">inc.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">61pd6n3t.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">mk1yd.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">a3mnw9.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">win.bin</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">vw06lg0y.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">qgp2s6z.exe</Image>
      </DnsQuery>
      <DnsQuery onmatch="include">
        <Image condition="end with">tt24n8xsl.exe</Image>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>