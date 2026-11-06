<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- Malicious executables (IOC) -->
        <Rule groupRelation="or">
          <Image condition="image">inc.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">0m6m882x2.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">2qfguc.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">3ctjhm3.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">7hhel.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">7l73h.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">72wiof7.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">78d359a87ae75ece08976e8b14d877fe.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">a3mnw9.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">akira_cobalt-strike_glassworm_poet-rat.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">bjiw49.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">hi9lezv.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">h3odp7l2u.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">k0d649u.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">mk1yd.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">qgp2s6z.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">tt24n8xsl.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">vw06lg0y.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">win.bin</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">x86_64-unknown-linux-esxi.elf</Image>
        </Rule>

        <!-- Malicious domains (IOC) -->
        <Rule groupRelation="or">
          <DestinationHostname condition="is">incblog.su</DestinationHostname>
        </Rule>
        <Rule groupRelation="or">
          <DestinationHostname condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</DestinationHostname>
        </Rule>
        <Rule groupRelation="or">
          <DestinationHostname condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</DestinationHostname>
        </Rule>

        <!-- Behavior: DNS poisoning / MiTM (T1557) -->
        <Rule groupRelation="or">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
        </Rule>

        <!-- Behavior: Application Layer C2 (T1071) -->
        <Rule groupRelation="or">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">80</DestinationPort>
        </Rule>
        <Rule groupRelation="or">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>

        <!-- Behavior: SMB admin share lateral movement (T1021.002) -->
        <Rule groupRelation="or">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
        </Rule>

        <!-- Behavior: RDP remote login (T1021.001) -->
        <Rule groupRelation="or">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
        </Rule>

        <!-- Behavior: Exfiltration over Web Service (T1567) – monitor outbound HTTPS to any host (no specific domains given) -->
        <Rule groupRelation="or">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">443</DestinationPort>
        </Rule>

        <!-- Behavior: Remote Access Tool traffic (T1219) – any outbound connection from listed RAT binaries -->
        <Rule groupRelation="or">
          <Image condition="image">inc.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">0m6m882x2.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">2qfguc.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">3ctjhm3.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">7hhel.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">7l73h.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">72wiof7.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">78d359a87ae75ece08976e8b14d877fe.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">a3mnw9.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">akira_cobalt-strike_glassworm_poet-rat.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">bjiw49.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">hi9lezv.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">h3odp7l2u.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">k0d649u.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">mk1yd.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">qgp2s6z.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">tt24n8xsl.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">vw06lg0y.exe</Image>
        </Rule>
        <Rule groupRelation="or">
          <Image condition="image">win.bin</Image>
        </Rule>

        <!-- Behavior: Service Execution leading to outbound traffic (T1569.002) – monitor any outbound TCP/UDP from services.exe spawning non‑allowlisted binaries -->
        <Rule groupRelation="or">
          <Image condition="image">services.exe</Image>
        </Rule>

        <!-- Behavior: Exploit Public‑Facing Application (T1190) – outbound connections from newly observed ELF payload -->
        <Rule groupRelation="or">
          <Image condition="image">x86_64-unknown-linux-esxi.elf</Image>
        </Rule>

      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>