<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- IOC: hash + filename -->
        <Rule groupRelation="and">
          <Image condition="end with">x86_64-unknown-linux-esxi.elf</Image>
          <Hashes condition="is">6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">h3odp7l2u.exe</Image>
          <Hashes condition="is">acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">hi9lezv.exe</Image>
          <Hashes condition="is">31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">072wiof7.exe</Image>
          <Hashes condition="is">1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">k0d649u.exe</Image>
          <Hashes condition="is">1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
          <Hashes condition="is">24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">2qfguc.exe</Image>
          <Hashes condition="is">589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">7hhel.exe</Image>
          <Hashes condition="is">5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">3ctjhm3.exe</Image>
          <Hashes condition="is">60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
          <Hashes condition="is">6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">bjiw49.exe</Image>
          <Hashes condition="is">765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">7l73h.exe</Image>
          <Hashes condition="is">7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
          <Hashes condition="is">8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">0m6m882x2.exe</Image>
          <Hashes condition="is">90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">inc.exe</Image>
          <Hashes condition="is">97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">61pd6n3t.exe</Image>
          <Hashes condition="is">bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">mk1yd.exe</Image>
          <Hashes condition="is">d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">a3mnw9.exe</Image>
          <Hashes condition="is">d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">win.bin</Image>
          <Hashes condition="is">dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">vw06lg0y.exe</Image>
          <Hashes condition="is">ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">qgp2s6z.exe</Image>
          <Hashes condition="is">f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">tt24n8xsl.exe</Image>
          <Hashes condition="is">ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b</Hashes>
        </Rule>

        <!-- BEHAVIOR: Service Execution (T1569.002) -->
        <Rule groupRelation="and">
          <OriginalFileName condition="is">sc.exe</OriginalFileName>
          <CommandLine condition="contains">create</CommandLine>
        </Rule>

        <!-- BEHAVIOR: Service Stop (T1489) -->
        <Rule groupRelation="and">
          <OriginalFileName condition="is">sc.exe</OriginalFileName>
          <CommandLine condition="contains">stop</CommandLine>
        </Rule>

        <!-- BEHAVIOR: Modify Registry (T1112) -->
        <Rule groupRelation="and">
          <OriginalFileName condition="is">reg.exe</OriginalFileName>
          <CommandLine condition="contains">add</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <OriginalFileName condition="is">reg.exe</OriginalFileName>
          <CommandLine condition="contains">delete</CommandLine>
        </Rule>

        <!-- BEHAVIOR: SMB Admin Share Lateral Movement (T1021.002) -->
        <Rule groupRelation="and">
          <OriginalFileName condition="is">net.exe</OriginalFileName>
          <CommandLine condition="contains">\\\\</CommandLine>
        </Rule>

        <!-- BEHAVIOR: Inhibit System Recovery (T1490) -->
        <Rule groupRelation="and">
          <OriginalFileName condition="is">vssadmin.exe</OriginalFileName>
          <CommandLine condition="contains">delete shadows</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <OriginalFileName condition="is">wbadmin.exe</OriginalFileName>
          <CommandLine condition="contains">delete catalog</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <OriginalFileName condition="is">diskshadow.exe</OriginalFileName>
          <CommandLine condition="contains">delete shadows all</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <OriginalFileName condition="is">bcdedit.exe</OriginalFileName>
          <CommandLine condition="contains">bootstatuspolicy ignoreallfailures</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <OriginalFileName condition="is">REAgentC.exe</OriginalFileName>
          <CommandLine condition="contains">/disable</CommandLine>
        </Rule>
        <Rule groupRelation="and">
          <OriginalFileName condition="is">wmic.exe</OriginalFileName>
          <CommandLine condition="contains">shadowcopy delete</CommandLine>
        </Rule>

        <!-- BEHAVIOR: Exploit Public-Facing Application – child process spawn (T1190) -->
        <Rule groupRelation="and">
          <ParentImage condition="end with">w3wp.exe</ParentImage>
          <Image condition="end with">cmd.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <ParentImage condition="end with">w3wp.exe</ParentImage>
          <Image condition="end with">powershell.exe</Image>
        </Rule>

        <!-- BEHAVIOR: Remote System Discovery (T1018) -->
        <Rule groupRelation="and">
          <Image condition="end with">ping.exe</Image>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">tracert.exe</Image>
        </Rule>

        <!-- BEHAVIOR: Remote Desktop Protocol (T1021.001) -->
        <Rule groupRelation="and">
          <Image condition="end with">mstsc.exe</Image>
        </Rule>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>