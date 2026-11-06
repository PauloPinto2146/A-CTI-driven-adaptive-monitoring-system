<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: known malicious hashes -->
      <ProcessCreate onmatch="include">
        <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
      </ProcessCreate>

      <!-- BEHAVIOR: T1033 – User Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">whoami.exe</Image>
        <CommandLine condition="is">whoami</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">query.exe</Image>
        <CommandLine condition="contains">user</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">qprocess.exe</Image>
        <CommandLine condition="contains">query user</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1218.011 – Rundll32 Abuse -->
      <ProcessCreate onmatch="include">
        <Image condition="is">rundll32.exe</Image>
        <CommandLine condition="contains">wininet.dll</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">rundll32.exe</Image>
        <CommandLine condition="contains">.cpl</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1543.003 – Windows Service Creation -->
      <ProcessCreate onmatch="include">
        <Image condition="is">sc.exe</Image>
        <CommandLine condition="contains">create</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1027 – Obfuscated/Encoded Commands -->
      <ProcessCreate onmatch="include">
        <Image condition="is">powershell.exe</Image>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1140 – Deobfuscate/Decode Files -->
      <ProcessCreate onmatch="include">
        <Image condition="is">certutil.exe</Image>
        <CommandLine condition="contains any">-decode;-decodehex</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">copy.exe</Image>
        <CommandLine condition="contains">/b</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1082 – System Information Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">systeminfo.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">wmic.exe</Image>
        <CommandLine condition="contains">computersystem get</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1016 – Network Configuration Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">ipconfig.exe</Image>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">netsh.exe</Image>
        <CommandLine condition="contains">interface ip show config</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">route.exe</Image>
        <CommandLine condition="contains">print</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1012 – Registry Query -->
      <ProcessCreate onmatch="include">
        <Image condition="is">reg.exe</Image>
        <CommandLine condition="contains">query</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1134 – Access Token Manipulation -->
      <ProcessCreate onmatch="include">
        <Image condition="is">runas.exe</Image>
        <CommandLine condition="contains">/user:</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1021 – Remote Services -->
      <ProcessCreate onmatch="include">
        <Image condition="is">mstsc.exe</Image>
        <CommandLine condition="contains">/v:</CommandLine>
      </ProcessCreate>
      <ProcessCreate onmatch="include">
        <Image condition="is">ssh.exe</Image>
        <CommandLine condition="contains">-l</CommandLine>
      </ProcessCreate>

      <!-- BEHAVIOR: T1018 – Remote System Discovery -->
      <ProcessCreate onmatch="include">
        <Image condition="is">net.exe</Image>
        <CommandLine condition="contains">view</CommandLine>
      </ProcessCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>