<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="include_malicious" groupRelation="or">
      <!-- IOC: specific malicious executable -->
      <ProcessCreate onmatch="include">
        <Image condition="is">wiseman.EXE</Image>
        <Hashes condition="is">SHA256:ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
      </ProcessCreate>

      <!-- T1033 – System Owner/User Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">whoami.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">query.exe</Image>
        <CommandLine condition="contains">user</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">net.exe</Image>
        <CommandLine condition="contains">user</CommandLine>
      </ProcessCreate>

      <!-- T1218.011 – Rundll32 Abuse -->
      <ProcessCreate onmatch="include">
        <Image condition="is">rundll32.exe</Image>
        <CommandLine condition="contains">.dll</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">rundll32.exe</Image>
        <CommandLine condition="contains">.cpl</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">rundll32.exe</Image>
        <CommandLine condition="contains">javascript:</CommandLine>
      </ProcessCreate>

      <!-- T1543.003 – Windows Service Creation/Modification -->
      <ProcessCreate onmatch="include">
        <Image condition="is">sc.exe</Image>
        <CommandLine condition="contains">create</CommandLine>
      </ProcessCreate>

      <!-- T1082 – System Information Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">systeminfo.exe</Image>
      </ProcessCreate>

      <!-- T1140 – Deobfuscate/Decode Files or Information -->
      <ProcessCreate onmatch="include">
        <Image condition="is">certutil.exe</Image>
        <CommandLine condition="contains">-decode</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">copy.exe</Image>
        <CommandLine condition="contains">/b</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">powershell.exe</Image>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
      </ProcessCreate>

      <!-- T1021 – Remote Services -->
      <ProcessCreate onmatch="include">
        <Image condition="is">mstsc.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">ssh.exe</Image>
      </ProcessCreate>

      <!-- T1112 – Modify Registry -->
      <ProcessCreate onmatch="include">
        <Image condition="is">reg.exe</Image>
        <CommandLine condition="contains">add</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">reg.exe</Image>
        <CommandLine condition="contains">delete</CommandLine>
      </ProcessCreate>

      <!-- T1012 – Query Registry -->
      <ProcessCreate onmatch="include">
        <Image condition="is">reg.exe</Image>
        <CommandLine condition="contains">query</CommandLine>
      </ProcessCreate>

      <!-- T1016 – System Network Configuration Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">ipconfig.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">netsh.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">route.exe</Image>
      </ProcessCreate>

      <!-- T1134 – Access Token Manipulation -->
      <ProcessCreate onmatch="include">
        <Image condition="is">runas.exe</Image>
      </ProcessCreate>

      <!-- T1018 – Remote System Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">net.exe</Image>
        <CommandLine condition="contains">view</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">ping.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">tracert.exe</Image>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>