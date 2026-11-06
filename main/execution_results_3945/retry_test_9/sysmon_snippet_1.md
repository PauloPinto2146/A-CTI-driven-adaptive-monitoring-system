<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.EXE -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">wiseman.exe</Image>
        <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
      </ProcessCreate>

      <!-- IOC: wininet.dll -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">wininet.dll</Image>
        <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
      </ProcessCreate>

      <!-- T1033 – System Owner/User Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">whoami.exe</Image>
        <CommandLine condition="contains">whoami</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="end with">query.exe</Image>
        <CommandLine condition="contains">user</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="end with">net.exe</Image>
        <CommandLine condition="contains">user</CommandLine>
      </ProcessCreate>

      <!-- T1218.011 – Rundll32 Abuse -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">rundll32.exe</Image>
        <CommandLine condition="contains any">.dll;.cpl;javascript:;mshtml</CommandLine>
      </ProcessCreate>

      <!-- T1543.003 – Windows Service Creation/Modification -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <CommandLine condition="contains any">create;config</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <CommandLine condition="contains any">New-Service;Set-Service</CommandLine>
      </ProcessCreate>

      <!-- T1082 – System Information Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">systeminfo.exe</Image>
        <CommandLine condition="contains">systeminfo</CommandLine>
      </ProcessCreate>

      <!-- T1140 – Deobfuscate/Decode Files or Information -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">certutil.exe</Image>
        <CommandLine condition="contains any">-decode;-decodehex</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="end with">copy.exe</Image>
        <CommandLine condition="contains">/b </CommandLine>
      </ProcessCreate>

      <!-- T1021 – Remote Services -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">mstsc.exe;rdpclip.exe;ssh.exe;psexec.exe</Image>
      </ProcessCreate>

      <!-- T1112 – Modify Registry -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <CommandLine condition="contains any">add;delete;save</CommandLine>
      </ProcessCreate>

      <!-- T1016 – System Network Configuration Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">ipconfig.exe;netsh.exe;route.exe;arp.exe</Image>
      </ProcessCreate>

      <!-- T1547.001 – Registry Run Keys / Startup Folder -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">reg.exe</Image>
        <CommandLine condition="contains any">HKLM\Software\Microsoft\Windows\CurrentVersion\Run;HKCU\Software\Microsoft\Windows\CurrentVersion\Run</CommandLine>
      </ProcessCreate>

      <!-- T1027 – Obfuscated Files or Information -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">7z.exe;winrar.exe;compact.exe</Image>
        <CommandLine condition="contains any">.zip;.7z</CommandLine>
      </ProcessCreate>

      <!-- T1134 – Access Token Manipulation -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">runas.exe</Image>
        <CommandLine condition="contains">runas /user:</CommandLine>
      </ProcessCreate>

      <!-- T1018 – Remote System Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is any">ping.exe;tracert.exe;net.exe</Image>
        <CommandLine condition="contains any">view;ping</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>