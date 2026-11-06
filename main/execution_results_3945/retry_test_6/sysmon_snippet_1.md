<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: specific executable hash (wiseman.exe) -->
      <ProcessCreate onmatch="include">
        <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
      </ProcessCreate>

      <!-- IOC: rundll32.exe loading wininet.dll -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">rundll32.exe</Image>
        <CommandLine condition="contains">wininet.dll</CommandLine>
      </ProcessCreate>

      <!-- T1033 – System Owner/User Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">whoami.exe</Image>
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
        <CommandLine condition="contains">.dll</CommandLine>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">rundll32.exe</Image>
        <CommandLine condition="contains">.cpl</CommandLine>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">rundll32.exe</Image>
        <CommandLine condition="contains">javascript:</CommandLine>
      </ProcessCreate>

      <!-- T1543.003 – Windows Service Creation / Modification -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <CommandLine condition="contains">create</CommandLine>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">sc.exe</Image>
        <CommandLine condition="contains">config</CommandLine>
      </ProcessCreate>

      <!-- T1082 – System Information Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">systeminfo.exe</Image>
      </ProcessCreate>

      <!-- T1140 – Deobfuscate/Decode Files -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">certutil.exe</Image>
        <CommandLine condition="contains">-decode</CommandLine>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">certutil.exe</Image>
        <CommandLine condition="contains">-decodehex</CommandLine>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">copy.exe</Image>
        <CommandLine condition="contains">/b</CommandLine>
      </ProcessCreate>

      <!-- T1027 – Obfuscated Files or Information -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">powershell.exe</Image>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
      </ProcessCreate>

      <!-- T1016 – System Network Configuration Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">ipconfig.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">ifconfig</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">route.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">netsh.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">arp.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">nbtstat.exe</Image>
      </ProcessCreate>

      <!-- T1018 – Remote System Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">net.exe</Image>
        <CommandLine condition="contains">view</CommandLine>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">ping.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">tracert.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">nslookup.exe</Image>
      </ProcessCreate>

      <!-- T1021 – Remote Services -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">mstsc.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">ssh.exe</Image>
      </ProcessCreate>

      <ProcessCreate onmatch="include">
        <Image condition="end with">vncviewer.exe</Image>
      </ProcessCreate>

      <!-- T1134 – Access Token Manipulation -->
      <ProcessCreate onmatch="include">
        <Image condition="end with">runas.exe</Image>
      </ProcessCreate>

      <!-- DERIVED – Masquerading (detect suspicious OriginalFileName) -->
      <ProcessCreate onmatch="include">
        <OriginalFileName condition="excludes any">*.*</OriginalFileName>
      </ProcessCreate>

      <!-- DERIVED – Persistence via Startup Folder -->
      <ProcessCreate onmatch="include">
        <Image condition="contains">Startup\</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>