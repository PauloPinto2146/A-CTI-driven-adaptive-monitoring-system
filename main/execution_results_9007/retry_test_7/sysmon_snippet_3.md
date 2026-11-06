<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: malicious binaries -->
        <Image condition="image">x86_64-unknown-linux-esxi.elf</Image>
        <Image condition="image">h3odp7l2u.exe</Image>
        <Image condition="image">hi9lezv.exe</Image>
        <Image condition="image">072wiof7.exe</Image>
        <Image condition="image">k0d649u.exe</Image>
        <Image condition="image">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
        <Image condition="image">2qfguc.exe</Image>
        <Image condition="image">7hhel.exe</Image>
        <Image condition="image">3ctjhm3.exe</Image>
        <Image condition="image">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
        <Image condition="image">bjiw49.exe</Image>
        <Image condition="image">7l73h.exe</Image>
        <Image condition="image">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
        <Image condition="image">0m6m882x2.exe</Image>
        <Image condition="image">inc.exe</Image>
        <Image condition="image">61pd6n3t.exe</Image>
        <Image condition="image">mk1yd.exe</Image>
        <Image condition="image">a3mnw9.exe</Image>
        <Image condition="image">win.bin</Image>
        <Image condition="image">vw06lg0y.exe</Image>
        <Image condition="image">qgp2s6z.exe</Image>
        <Image condition="image">tt24n8xsl.exe</Image>
        <!-- IOC: malicious domains -->
        <DestinationHostname condition="is">incblog.su</DestinationHostname>
        <DestinationHostname condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</DestinationHostname>
        <DestinationHostname condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</DestinationHostname>

        <!-- BEHAVIOR: Remote Desktop (RDP) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: SMB / Windows Admin Shares -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Suspicious use of common application‑layer protocols -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443;53;445</DestinationPort>
          <Image condition="excludes any">svchost.exe;explorer.exe;lsass.exe;services.exe;wininit.exe</Image>
        </Rule>

        <!-- BEHAVIOR: Service execution traffic (services.exe) -->
        <Image condition="image">services.exe</Image>

        <!-- BEHAVIOR: Potential DNS/ARP poisoning (DNS traffic) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- BEHAVIOR: Exfiltration over Web Services (HTTP/HTTPS) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>