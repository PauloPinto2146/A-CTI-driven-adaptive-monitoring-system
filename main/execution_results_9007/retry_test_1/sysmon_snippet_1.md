<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: known malicious filenames and hashes -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">x86_64-unknown-linux-esxi.elf;h3odp7l2u.exe;hi9lezv.exe;072wiof7.exe;k0d649u.exe;2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat;2qfguc.exe;7hhel.exe;3ctjhm3.exe;2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat;bjiw49.exe;7l73h.exe;2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat;0m6m882x2.exe;inc.exe;61pd6n3t.exe;mk1yd.exe;a3mnw9.exe;win.bin;vw06lg0y.exe;qgp2s6z.exe;tt24n8xsl.exe</Image>
        <Hashes condition="is any">6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141;acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4;31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502;1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449;1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11;24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7;589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880;5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241;60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6;6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f;765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a;7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245;8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4;90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c;97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2;bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc;d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570;d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb;dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da;ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22;f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347;ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b</Hashes>
      </ProcessCreate>

      <!-- Credential Dumping (T1003) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">lsass.exe;procdump.exe;mimikatz.exe;dumppriv.exe</Image>
        <CommandLine condition="contains">lsass</CommandLine>
      </ProcessCreate>

      <!-- Service Stop / Disable (T1489) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">sc.exe;net.exe;powershell.exe</Image>
        <CommandLine condition="contains any">stop;disable;delete;change;config</CommandLine>
        <CommandLine condition="contains any">MSExchangeIS;SQLSERVERAGENT</CommandLine>
      </ProcessCreate>

      <!-- SMB Admin Share Lateral Movement (T1021.002) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">psexec.exe;wmic.exe;net.exe</Image>
        <CommandLine condition="contains">\\</CommandLine>
        <CommandLine condition="contains any">ADMIN$;C$;IPC$</CommandLine>
      </ProcessCreate>

      <!-- Registry Modification (T1112) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">reg.exe;powershell.exe</Image>
        <CommandLine condition="contains any">HKLM\Software\Microsoft\Windows\CurrentVersion\Run;HKLM\System\CurrentControlSet\Services;HKCU\Software\Microsoft\Windows\CurrentVersion\Run</CommandLine>
      </ProcessCreate>

      <!-- Phishing Execution (T1566) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">wscript.exe;cscript.exe;mshta.exe;powershell.exe</Image>
        <CommandLine condition="contains any">/e:vbscript;/EncodedCommand;/c;/b</CommandLine>
      </ProcessCreate>

      <!-- Exploit Public-Facing Application (T1190) -->
      <ProcessCreate onmatch="include">
        <ParentImage condition="is">w3wp.exe</ParentImage>
        <Image condition="is any">cmd.exe;powershell.exe;msbuild.exe;cscript.exe</Image>
      </ProcessCreate>

      <!-- Remote Desktop Protocol (T1021.001) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">mstsc.exe;rdpclip.exe;svchost.exe</Image>
        <CommandLine condition="contains">/v:</CommandLine>
      </ProcessCreate>

      <!-- Service Execution (T1569.002) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">sc.exe;net.exe;psexec.exe</Image>
        <CommandLine condition="contains any">create;config</CommandLine>
      </ProcessCreate>

      <!-- Inhibit System Recovery (T1490) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">vssadmin.exe;wbadmin.exe;diskshadow.exe;bcdedit.exe;REAgentC.exe;wmic.exe</Image>
        <CommandLine condition="contains any">delete shadows;delete /all;bootstatuspolicy ignoreallfailures;recoveryenabled no</CommandLine>
      </ProcessCreate>

      <!-- Software Packing (T1027.002) -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">upx.exe;mpress.exe</Image>
        <CommandLine condition="contains any">-d;-unpack</CommandLine>
      </ProcessCreate>

      <!-- Remote Access Tools Persistence (T1219) -->
      <ProcessCreate onmatch="include">
        <ParentImage condition="contains">remotesupport</ParentImage>
        <CurrentDirectory condition="contains any">%TEMP%;%APPDATA%</CurrentDirectory>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>