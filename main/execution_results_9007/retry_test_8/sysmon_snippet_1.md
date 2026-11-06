<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- IOC rules -->
        <Rule>
          <Image condition="is">x86_64-unknown-linux-esxi.elf</Image>
        </Rule>
        <Rule>
          <Image condition="is">h3odp7l2u.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">hi9lezv.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">072wiof7.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">k0d649u.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
        </Rule>
        <Rule>
          <Image condition="is">2qfguc.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">7hhel.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">3ctjhm3.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
        </Rule>
        <Rule>
          <Image condition="is">bjiw49.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">7l73h.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
        </Rule>
        <Rule>
          <Image condition="is">0m6m882x2.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">inc.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">61pd6n3t.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">mk1yd.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">a3mnw9.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">win.bin</Image>
        </Rule>
        <Rule>
          <Image condition="is">vw06lg0y.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">qgp2s6z.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">tt24n8xsl.exe</Image>
        </Rule>

        <!-- BEHAVIOR rules -->
        <Rule>
          <Image condition="is">sc.exe</Image>
          <CommandLine condition="contains any">stop;delete</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">sc.exe</Image>
          <CommandLine condition="contains any">create;config;start</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">net.exe</Image>
          <CommandLine condition="contains any">create;config;start</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">psexec.exe</Image>
          <CommandLine condition="contains any">create;config;start</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">reg.exe</Image>
          <CommandLine condition="contains">add</CommandLine>
          <CommandLine condition="contains any">Run;Services;Security</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">regsvr32.exe</Image>
          <CommandLine condition="contains">/i</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">vssadmin.exe</Image>
          <CommandLine condition="contains any">delete;shadow;all</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">wbadmin.exe</Image>
          <CommandLine condition="contains any">delete;catalog</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">diskshadow.exe</Image>
          <CommandLine condition="contains any">delete;shadows</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">bcdedit.exe</Image>
          <CommandLine condition="contains any">bootstatuspolicy;recoveryenabled</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">REAgentC.exe</Image>
          <CommandLine condition="contains any">disable</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">wmic.exe</Image>
          <CommandLine condition="contains any">shadowcopy;delete</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">w3wp.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">mstsc.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">termsrv.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">net.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">ping.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">tracert.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">arp.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">outlook.exe</Image>
        </Rule>
        <Rule>
          <Image condition="is">powershell.exe</Image>
          <CommandLine condition="contains">-EncodedCommand</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">powershell.exe</Image>
          <CommandLine condition="contains any">ADMIN$;C$</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">cipher.exe</Image>
          <CommandLine condition="contains">/e</CommandLine>
        </Rule>
        <Rule>
          <Image condition="is">vssadmin.exe</Image>
          <CommandLine condition="contains">/e</CommandLine>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>