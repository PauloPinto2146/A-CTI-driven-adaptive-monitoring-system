<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="MaliciousIoC" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC – malicious executable filenames -->
        <Rule groupRelation="or">
          <Image condition="is any">x86_64-unknown-linux-esxi.elf;h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;win.bin;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</Image>
        </Rule>

        <!-- IOC – malicious destination hostnames -->
        <Rule groupRelation="or">
          <DestinationHostname condition="is">incblog.su</DestinationHostname>
        </Rule>
        <Rule groupRelation="or">
          <DestinationHostname condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</DestinationHostname>
        </Rule>
        <Rule groupRelation="or">
          <DestinationHostname condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</DestinationHostname>
        </Rule>

        <!-- BEHAVIOR – DNS (AiTM) -->
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- BEHAVIOR – HTTP (App‑layer C2 / exfil) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">80</DestinationPort>
        </Rule>

        <!-- BEHAVIOR – HTTPS (App‑layer C2 / exfil) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>

        <!-- BEHAVIOR – SMB admin share (Lateral movement) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
        </Rule>

        <!-- BEHAVIOR – SMB/NetBIOS enumeration (Remote system discovery) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">139</DestinationPort>
        </Rule>

        <!-- BEHAVIOR – RDP (Remote desktop) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- BEHAVIOR – Service execution (T1569.002) -->
        <Rule groupRelation="and">
          <Image condition="is any">sc.exe;net.exe;services.exe</Image>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED – PowerShell over web (T1071) -->
        <Rule groupRelation="and">
          <Image condition="image">powershell.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443</DestinationPort>
        </Rule>

        <!-- DERIVED – WMIC / WinRS over SMB (T1569.002) -->
        <Rule groupRelation="and">
          <Image condition="is any">wmic.exe;winrs.exe</Image>
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
        </Rule>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>