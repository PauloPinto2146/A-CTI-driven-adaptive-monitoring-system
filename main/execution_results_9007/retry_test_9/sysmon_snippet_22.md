<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC – suspicious domains -->
      <DnsQuery>
        <QueryName condition="is">incblog.su</QueryName>
      </DnsQuery>
      <DnsQuery>
        <QueryName condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</QueryName>
      </DnsQuery>
      <DnsQuery>
        <QueryName condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</QueryName>
      </DnsQuery>

      <!-- IOC – suspicious executables / binaries -->
      <DnsQuery>
        <Image condition="is">x86_64-unknown-linux-esxi.elf</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">h3odp7l2u.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">hi9lezv.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">072wiof7.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">k0d649u.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">2qfguc.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">7hhel.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">3ctjhm3.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">bjiw49.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">7l73h.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">0m6m882x2.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">inc.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">61pd6n3t.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">mk1yd.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">a3mnw9.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">win.bin</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">vw06lg0y.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">qgp2s6z.exe</Image>
      </DnsQuery>
      <DnsQuery>
        <Image condition="is">tt24n8xsl.exe</Image>
      </DnsQuery>

      <!-- BEHAVIOR – DNS failures indicative of poisoning or tunneling (T1557) -->
      <DnsQuery>
        <QueryStatus condition="is any">NXDOMAIN;REFUSED</QueryStatus>
      </DnsQuery>

      <!-- BEHAVIOR – Successful responses that may be used for data exfiltration over DNS (T1071) -->
      <DnsQuery>
        <QueryStatus condition="is">NOERROR</QueryStatus>
      </DnsQuery>
    </RuleGroup>
  </EventFiltering>
</Sysmon>