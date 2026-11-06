<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- IOC: known malicious file hashes -->
    <RuleGroup name="IOC_hashes" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Hashes condition="is any">6cd349eda0fa6c8b274a0920852c68f8b727afea1fdbc69ad183cef05d9cf141;acce811c4fc2a6e3fddd4231e386f1648ca44f039d2d275316bc0a0fc96e0af4;31800380c359143ae82c4f9011eee653dd22443d03d6a499148203bbfc275502;1898d056463284d849801cbdea6a3dec6c9f568f01569912c3868a5eea9a5449;1d10d8f5a420d0e4683b4cb40bcf0c984d1e7ea1f3b4442a00a525584632ac11;24f6c0ca39b2a5593086ff56d818ddfbde121f8e44d54faa762e510397dc9db7;589d9480fbfec2d8e61638eb0b537183d0f9977411fd1d2c0f8eb611feebe880;5cc212f84d2bf3fbab165aaf09b16e00fcf2f1ccd880d24b14404c53dcdbf241;60aeb9f7bccf377ff02ed64783e66a62c0f976878d9729b067bc7e5b0b9da9d6;6bf155b269d452f3c3b62832b27bbebe4da436e228dbf521155b1d5989e3743f;765508aa2ec6a1b73a76a23f4fa559d32355622748c91a46ed7b315eae2ee60a;7f37351979c249417cb180b4ede0ed17e5fe2a1f08add4d72606b589f8fdb245;8d1a22c430252f29611766b8e4a82af0fba60d609246463466b384d6d4793df4;90e46e89fec2108a1cb4850bb33e3563e92a14d04e1e613ac8c9311f152d294c;97aebda5482899fef84a24e456bff055acaa47e5ab4029f768d9e0c62a660ce2;bf8c45e5aa9551a17eefbd1d179422c32b4309c47ee9a3f315bb80ed6d4f7efc;d26bfb0147f60dc6500a9298d521ee67b49daaf4b8f8be54e7cc8fd86a597570;d65120291dee76c694f8bea54841f7f68329b499b28f4aee5ea5c9369a7432cb;dc9938f51150d13a69fc25f3f19052eacb1bf0a086fd5cf39762501fb3ddd7da;ea721240c14e3d14f8d88e0020880448c6c602f1180a1e5dbe40871cfeedcc22;f6a01d0246ce31faf6938ea488086d4358505405a4ef5c5faa482e79e92cb347;ff5da8f0330a4c581c37284c74aae2683c007dc6e406e1e2e6803e7bb398b77b</Hashes>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Service Stop (T1489) -->
    <RuleGroup name="Service_Stop_sc" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">sc.exe</Image>
        <CommandLine condition="contains">stop</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">sc.exe</Image>
        <CommandLine condition="contains">config</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Inhibit System Recovery (T1490) -->
    <RuleGroup name="Inhibit_Recovery" groupRelation="or">
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
        <CommandLine condition="contains">delete shadows all</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">bcdedit.exe</Image>
        <CommandLine condition="contains">bootstatuspolicy ignoreallfailures</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">bcdedit.exe</Image>
        <CommandLine condition="contains">recoveryenabled no</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">wmic.exe</Image>
        <CommandLine condition="contains">shadowcopy delete</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Registry Modification (T1112) -->
    <RuleGroup name="Registry_Modification" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">reg.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">regedit.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Obfuscated/Packed Execution (T1027.002) -->
    <RuleGroup name="Obfuscated_Execution" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">cmd.exe</Image>
        <CommandLine condition="contains">/c</CommandLine>
        <CommandLine condition="contains">base64</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: SMB Admin Share Access (T1021.002) -->
    <RuleGroup name="SMB_Admin_Share" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="contains">ADMIN$</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="contains">C$</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Remote Service Execution (T1569.002) -->
    <RuleGroup name="Remote_Service_Exec" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">psexec.exe</Image>
        <CommandLine condition="contains">\\\\</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">sc.exe</Image>
        <CommandLine condition="contains">create</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Exploit Public-Facing Application (T1190) -->
    <RuleGroup name="Exploit_w3wp" groupRelation="or">
      <ProcessCreate onmatch="include">
        <ParentImage condition="image">w3wp.exe</ParentImage>
        <Image condition="image">cmd.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <ParentImage condition="image">w3wp.exe</ParentImage>
        <Image condition="image">powershell.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Remote System Discovery (T1018) -->
    <RuleGroup name="Remote_Discovery" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">ping.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">tracert.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="contains">view</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Remote Desktop Logon (T1021.001) -->
    <RuleGroup name="RDP_Logon" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">mstsc.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Remote Access Tool (T1219) -->
    <RuleGroup name="Remote_Access_Tool" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="contains">remote</Image>
        <CommandLine condition="contains">-service</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Credential Dumping (T1003) -->
    <RuleGroup name="Credential_Dumping" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">lsass.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">procdump.exe</Image>
      </ProcessCreate>
    </RuleGroup>

    <!-- BEHAVIOR: Data Encrypted for Impact (T1486) -->
    <RuleGroup name="Ransomware_FileWrite" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">cipher.exe</Image>
        <CommandLine condition="contains">/e</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <CommandLine condition="contains">-enc</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>