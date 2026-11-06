<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <NetworkConnect onmatch="include">
        <!-- IOC: known malicious executables -->
        <Image condition="is any">x86_64-unknown-linux-esxi.elf;h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a;bjiw49.exe;7l73h.exe;8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2;inc.exe;61pd6n3t.exe;mk1yd.exe;d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb;a3mnw9.exe;dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da;win.bin;ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22;vw06lg0y.exe;f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347;qgp2s6z.exe;ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b;tt24n8xsl.exe</Image>

        <!-- IOC: known malicious domains -->
        <DestinationHostname condition="is any">incblog.su;incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion;incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</DestinationHostname>

        <!-- BEHAVIOR: suspicious outbound HTTPS (port 443) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">443</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: SMB admin‑share activity -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">445</DestinationPort>
          <Initiated condition="is">true</Initiated>
          <Image condition="is any">cmd.exe;powershell.exe;wmic.exe</Image>
        </Rule>

        <!-- BEHAVIOR: Remote Desktop (RDP) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">3389</DestinationPort>
          <Initiated condition="is">true</Initiated>
          <Image condition="is any">mstsc.exe;rdpclip.exe</Image>
        </Rule>

        <!-- BEHAVIOR: DNS traffic (possible C2) -->
        <Rule groupRelation="and">
          <Protocol condition="is">udp</Protocol>
          <DestinationPort condition="is">53</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- BEHAVIOR: Exploitation of vulnerable public‑facing apps (FortiClient EMS, SimpleHelp) -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is any">80;443;8443</DestinationPort>
          <Initiated condition="is">true</Initiated>
          <Image condition="is any">forticlientems.exe;simplehelp.exe</Image>
        </Rule>

        <!-- DERIVED: outbound SSH -->
        <Rule groupRelation="and">
          <Protocol condition="is">tcp</Protocol>
          <DestinationPort condition="is">22</DestinationPort>
          <Initiated condition="is">true</Initiated>
        </Rule>

        <!-- DERIVED: remote system discovery utilities -->
        <Image condition="is any">net.exe;ping.exe;tracert.exe</Image>
      </NetworkConnect>
    </RuleGroup>
  </EventFiltering>
</Sysmon>