<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: Wiseman executable with known SHA‑256 -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\wiseman.exe</Image>
        <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
      </ProcessCreate>

      <!-- IOC: WinInet DLL -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\wininet.dll</Image>
      </ProcessCreate>

      <!-- T1033 – System Owner/User Discovery (whoami) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\whoami.exe</Image>
      </ProcessCreate>

      <!-- T1218.011 – Rundll32 Abuse (loading DLLs) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\rundll32.exe</Image>
        <CommandLine condition="contains">.dll</CommandLine>
      </ProcessCreate>

      <!-- T1543.003 – Windows Service Creation/Modification (sc.exe) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\sc.exe</Image>
        <CommandLine condition="contains">create</CommandLine>
      </ProcessCreate>

      <!-- T1082 – System Information Discovery (systeminfo) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\systeminfo.exe</Image>
      </ProcessCreate>

      <!-- T1140 – Deobfuscate/Decode Files (certutil) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\certutil.exe</Image>
        <CommandLine condition="contains">-decode</CommandLine>
      </ProcessCreate>

      <!-- T1027 – Obfuscated Files or Information (PowerShell Base64) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\powershell.exe</Image>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
      </ProcessCreate>

      <!-- T1012 – Query Registry -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\reg.exe</Image>
        <CommandLine condition="contains">query</CommandLine>
      </ProcessCreate>

      <!-- T1134 – Access Token Manipulation (runas) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\runas.exe</Image>
      </ProcessCreate>

      <!-- T1018 – Remote System Discovery (net view) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\net.exe</Image>
        <CommandLine condition="contains">view</CommandLine>
      </ProcessCreate>

      <!-- T1018 – Remote System Discovery (ping) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\ping.exe</Image>
      </ProcessCreate>

      <!-- T1018 – Remote System Discovery (tracert) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\tracert.exe</Image>
      </ProcessCreate>

      <!-- T1016 – System Network Configuration Discovery (ipconfig) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\ipconfig.exe</Image>
      </ProcessCreate>

      <!-- T1016 – System Network Configuration Discovery (ifconfig) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\ifconfig.exe</Image>
      </ProcessCreate>

      <!-- T1016 – System Network Configuration Discovery (route) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\route.exe</Image>
      </ProcessCreate>

      <!-- T1016 – System Network Configuration Discovery (arp) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\arp.exe</Image>
      </ProcessCreate>

      <!-- T1021 – Remote Services (RDP) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\mstsc.exe</Image>
      </ProcessCreate>

      <!-- T1021 – Remote Services (PsExec) -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">\psexec.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>