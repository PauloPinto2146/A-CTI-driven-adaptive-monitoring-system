<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: x86_64-unknown-linux-esxi.elf -->
      <ProcessCreate onmatch="include">
        <Image condition="image">x86_64-unknown-linux-esxi.elf</Image>
        <Hashes condition="is">6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141</Hashes>
      </ProcessCreate>
      <!-- IOC: h3odp7l2u.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">h3odp7l2u.exe</Image>
        <Hashes condition="is">acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4</Hashes>
      </ProcessCreate>
      <!-- IOC: hi9lezv.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">hi9lezv.exe</Image>
        <Hashes condition="is">31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502</Hashes>
      </ProcessCreate>
      <!-- IOC: 072wiof7.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">072wiof7.exe</Image>
        <Hashes condition="is">1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449</Hashes>
      </ProcessCreate>
      <!-- IOC: k0d649u.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">k0d649u.exe</Image>
        <Hashes condition="is">1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11</Hashes>
      </ProcessCreate>
      <!-- IOC: 2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat -->
      <ProcessCreate onmatch="include">
        <Image condition="image">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
        <Hashes condition="is">24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7</Hashes>
      </ProcessCreate>
      <!-- IOC: 2qfguc.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">2qfguc.exe</Image>
        <Hashes condition="is">589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880</Hashes>
      </ProcessCreate>
      <!-- IOC: 7hhel.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">7hhel.exe</Image>
        <Hashes condition="is">5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241</Hashes>
      </ProcessCreate>
      <!-- IOC: 3ctjhm3.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">3ctjhm3.exe</Image>
        <Hashes condition="is">60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6</Hashes>
      </ProcessCreate>
      <!-- IOC: 2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat -->
      <ProcessCreate onmatch="include">
        <Image condition="image">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
        <Hashes condition="is">6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f</Hashes>
      </ProcessCreate>
      <!-- IOC: bjiw49.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">bjiw49.exe</Image>
        <Hashes condition="is">765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a</Hashes>
      </ProcessCreate>
      <!-- IOC: 7l73h.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">7l73h.exe</Image>
        <Hashes condition="is">7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245</Hashes>
      </ProcessCreate>
      <!-- IOC: 2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat -->
      <ProcessCreate onmatch="include">
        <Image condition="image">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
        <Hashes condition="is">8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4</Hashes>
      </ProcessCreate>
      <!-- IOC: 0m6m882x2.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">0m6m882x2.exe</Image>
        <Hashes condition="is">90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c</Hashes>
      </ProcessCreate>
      <!-- IOC: inc.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">inc.exe</Image>
        <Hashes condition="is">97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2</Hashes>
      </ProcessCreate>
      <!-- IOC: 61pd6n3t.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">61pd6n3t.exe</Image>
        <Hashes condition="is">bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc</Hashes>
      </ProcessCreate>
      <!-- IOC: mk1yd.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">mk1yd.exe</Image>
        <Hashes condition="is">d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570</Hashes>
      </ProcessCreate>
      <!-- IOC: a3mnw9.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">a3mnw9.exe</Image>
        <Hashes condition="is">d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb</Hashes>
      </ProcessCreate>
      <!-- IOC: win.bin -->
      <ProcessCreate onmatch="include">
        <Image condition="image">win.bin</Image>
        <Hashes condition="is">dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da</Hashes>
      </ProcessCreate>
      <!-- IOC: vw06lg0y.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">vw06lg0y.exe</Image>
        <Hashes condition="is">ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22</Hashes>
      </ProcessCreate>
      <!-- IOC: qgp2s6z.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">qgp2s6z.exe</Image>
        <Hashes condition="is">f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347</Hashes>
      </ProcessCreate>
      <!-- IOC: tt24n8xsl.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">tt24n8xsl.exe</Image>
        <Hashes condition="is">ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b</Hashes>
      </ProcessCreate>

      <!-- BEHAVIOR: Service Stop (T1489) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">sc.exe</Image>
        <CommandLine condition="contains">stop</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="contains">stop</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <CommandLine condition="contains">Stop-Service</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Registry Modification (T1112) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">reg.exe</Image>
        <CommandLine condition="contains">add</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">reg.exe</Image>
        <CommandLine condition="contains">delete</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <CommandLine condition="contains">Set-ItemProperty</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Inhibit System Recovery (T1490) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">vssadmin.exe</Image>
        <CommandLine condition="contains">delete shadows</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">wbadmin.exe</Image>
        <CommandLine condition="contains">delete catalog</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">diskshadow.exe</Image>
        <CommandLine condition="contains">delete shadows</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">bcdedit.exe</Image>
        <CommandLine condition="contains">bootstatuspolicy ignoreallfailures</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">REAgentC.exe</Image>
        <CommandLine condition="contains">/disable</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">wmic.exe</Image>
        <CommandLine condition="contains">shadowcopy delete</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Exploit Public‑Facing Application (T1190) -->
      <ProcessCreate onmatch="include">
        <ParentImage condition="image">w3wp.exe</ParentImage>
        <Image condition="image">cmd.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <ParentImage condition="image">w3wp.exe</ParentImage>
        <Image condition="image">powershell.exe</Image>
      </ProcessCreate>

      <!-- BEHAVIOR: SMB/Windows Admin Shares (T1021.002) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">psexec.exe</Image>
        <CommandLine condition="contains">\\ADMIN$</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">wmic.exe</Image>
        <CommandLine condition="contains">\\C$</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="contains">use \\ADMIN$</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Remote System Discovery (T1018) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">cmd.exe</Image>
        <CommandLine condition="contains">net view</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">ping.exe</Image>
        <CommandLine condition="contains">ping</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">tracert.exe</Image>
        <CommandLine condition="contains">tracert</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">arp.exe</Image>
        <CommandLine condition="contains">arp</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">nslookup.exe</Image>
        <CommandLine condition="contains">nslookup</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Service Execution (T1569.002) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">sc.exe</Image>
        <CommandLine condition="contains">create</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="contains">start</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">psexec.exe</Image>
        <CommandLine condition="contains">-s</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Data Encrypted for Impact (T1486) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">cipher.exe</Image>
        <CommandLine condition="contains">/e</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <CommandLine condition="contains">-enc</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Remote Access Tools Persistence (T1219) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">sc.exe</Image>
        <CommandLine condition="contains">create</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <CommandLine condition="contains">-NoExit</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Remote Desktop Protocol (T1021.001) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">mstsc.exe</Image>
      </ProcessCreate>

    </RuleGroup>
  </EventFiltering>
</Sysmon>