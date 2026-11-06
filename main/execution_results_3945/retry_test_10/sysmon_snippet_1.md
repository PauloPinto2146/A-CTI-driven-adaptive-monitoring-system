<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.exe with known SHA‑256 -->
      <ProcessCreate onmatch="include">
        <Image condition="image">wiseman.exe</Image>
        <Hashes condition="is">SHA256:ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
      </ProcessCreate>

      <!-- BEHAVIOR: Rundll32 abused for DLL/CPL/JavaScript execution -->
      <ProcessCreate onmatch="include">
        <Image condition="image">rundll32.exe</Image>
        <CommandLine condition="contains any">.dll;.cpl;javascript:</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Service creation/modification via sc.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">sc.exe</Image>
        <CommandLine condition="contains any">create;config</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: PowerShell encoded payloads -->
      <ProcessCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <CommandLine condition="contains any">-EncodedCommand;-enc</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Certutil decoding -->
      <ProcessCreate onmatch="include">
        <Image condition="image">certutil.exe</Image>
        <CommandLine condition="contains any">-decode;-decodebase64</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Registry Run‑Key manipulation via reg.exe -->
      <ProcessCreate onmatch="include">
        <Image condition="image">reg.exe</Image>
        <CommandLine condition="contains">add</CommandLine>
        <CommandLine condition="contains">HKLM\</CommandLine>
        <CommandLine condition="contains">Run</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: System Owner/User discovery (whoami) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">whoami.exe</Image>
        <CommandLine condition="is">whoami</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: User enumeration via query -->
      <ProcessCreate onmatch="include">
        <Image condition="image">query.exe</Image>
        <CommandLine condition="contains">user</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: User enumeration via net -->
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="contains">user</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: System Information discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="image">systeminfo.exe</Image>
        <CommandLine condition="is">systeminfo</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Network configuration discovery (ipconfig) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">ipconfig.exe</Image>
        <CommandLine condition="is">ipconfig /all</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Network configuration discovery (netsh) -->
      <ProcessCreate onmatch="include">
        <Image condition="image">netsh.exe</Image>
        <CommandLine condition="contains">interface ip show</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Routing table discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="image">route.exe</Image>
        <CommandLine condition="contains">print</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Remote system discovery via ping -->
      <ProcessCreate onmatch="include">
        <Image condition="image">ping.exe</Image>
      </ProcessCreate>

      <!-- BEHAVIOR: Remote system enumeration via net view -->
      <ProcessCreate onmatch="include">
        <Image condition="image">net.exe</Image>
        <CommandLine condition="is">net view</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Token manipulation via runas -->
      <ProcessCreate onmatch="include">
        <Image condition="image">runas.exe</Image>
        <CommandLine condition="contains">/user:</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Remote desktop (RDP) connections -->
      <ProcessCreate onmatch="include">
        <Image condition="image">mstsc.exe</Image>
        <CommandLine condition="contains">/v:</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: Remote execution with PsExec -->
      <ProcessCreate onmatch="include">
        <Image condition="image">psexec.exe</Image>
        <CommandLine condition="contains">\</CommandLine>
      </ProcessCreate>

      <!-- DERIVED: Explorer spawning Rundll32 with a DLL argument (T1218.011) -->
      <ProcessCreate onmatch="include">
        <ParentImage condition="image">explorer.exe</ParentImage>
        <Image condition="image">rundll32.exe</Image>
        <CommandLine condition="contains">.dll</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>