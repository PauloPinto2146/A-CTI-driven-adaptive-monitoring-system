<Sysmon schemaversion="4.40">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: malicious executables initiating any connection -->
        <Rule groupRelation="or"><Image condition="image">inc.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">x86_64-unknown-linux-esxi.elf</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">h3odp7l2u.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">hi9lezv.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">072wiof7.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">k0d649u.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">2qfguc.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">7hhel.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">3ctjhm3.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">bjiw49.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">7l73h.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">0m6m882x2.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">61pd6n3t.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">mk1yd.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">a3mnw9.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">win.bin</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">vw06lg0y.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">qgp2s6z.exe</Image></Rule>
        <Rule groupRelation="or"><Image condition="image">tt24n8xsl.exe</Image></Rule>

        <!-- IOC: connections to malicious domains -->
        <Rule groupRelation="or"><DestinationHostname condition="is">incblog.su</DestinationHostname></Rule>
        <Rule groupRelation="or"><DestinationHostname condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</DestinationHostname></Rule>
        <Rule groupRelation="or"><DestinationHostname condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</DestinationHostname></Rule>

        <!-- BEHAVIOR: SMB admin share lateral movement (T1021.002) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Application‑layer C2 over HTTP/HTTPS (T1071) using typical LOE tools -->
        <Rule groupRelation="and">
          <Image condition="image">powershell.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">cmd.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">cscript.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">wscript.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">pwsh.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Exfiltration over Web Services (T1567) – any process to .onion or .su domains -->
        <Rule groupRelation="and">
          <DestinationHostname condition="contains">.onion</DestinationHostname>
          <Initiated condition="is">true</Initiated>
        </Rule>
        <Rule groupRelation="and">
          <DestinationHostname condition="contains">.su</DestinationHostname>
          <Initiated condition="is">true</Initiated>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>