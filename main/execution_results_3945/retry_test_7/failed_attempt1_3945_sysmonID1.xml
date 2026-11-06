<EventFiltering>
  <RuleGroup name="" groupRelation="or">
    <!-- IOC: wiseman.EXE -->
    <ProcessCreate onmatch="include">
      <Image condition="image">wiseman.exe</Image>
      <Hashes condition="is">SHA256=ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
    </ProcessCreate>

    <!-- IOC: wininet.dll -->
    <ProcessCreate onmatch="include">
      <Image condition="image">wininet.dll</Image>
      <Hashes condition="is">SHA256=fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
    </ProcessCreate>

    <!-- T1033: whoami -->
    <ProcessCreate onmatch="include">
      <Image condition="image">whoami.exe</Image>
      <CommandLine condition="is">whoami</CommandLine>
    </ProcessCreate>

    <!-- T1033: query user -->
    <ProcessCreate onmatch="include">
      <Image condition="image">query.exe</Image>
      <CommandLine condition="contains">query user</CommandLine>
    </ProcessCreate>

    <!-- T1082: systeminfo -->
    <ProcessCreate onmatch="include">
      <Image condition="image">systeminfo.exe</Image>
      <CommandLine condition="is">systeminfo</CommandLine>
    </ProcessCreate>

    <!-- T1016: ipconfig -->
    <ProcessCreate onmatch="include">
      <Image condition="image">ipconfig.exe</Image>
      <CommandLine condition="contains">ipconfig</CommandLine>
    </ProcessCreate>

    <!-- T1016: route -->
    <ProcessCreate onmatch="include">
      <Image condition="image">route.exe</Image>
      <CommandLine condition="contains">route</CommandLine>
    </ProcessCreate>

    <!-- T1018: net view -->
    <ProcessCreate onmatch="include">
      <Image condition="image">net.exe</Image>
      <CommandLine condition="contains">net view</CommandLine>
    </ProcessCreate>

    <!-- T1218.011: rundll32 .cpl -->
    <ProcessCreate onmatch="include">
      <Image condition="image">rundll32.exe</Image>
      <CommandLine condition="contains">.cpl</CommandLine>
    </ProcessCreate>

    <!-- T1218.011: rundll32 javascript -->
    <ProcessCreate onmatch="include">
      <Image condition="image">rundll32.exe</Image>
      <CommandLine condition="contains">javascript:</CommandLine>
    </ProcessCreate>

    <!-- T1543.003: sc create -->
    <ProcessCreate onmatch="include">
      <Image condition="image">sc.exe</Image>
      <CommandLine condition="contains">create</CommandLine>
    </ProcessCreate>

    <!-- T1012: reg query -->
    <ProcessCreate onmatch="include">
      <Image condition="image">reg.exe</Image>
      <CommandLine condition="contains">query</CommandLine>
    </ProcessCreate>

    <!-- T1140: certutil decode -->
    <ProcessCreate onmatch="include">
      <Image condition="image">certutil.exe</Image>
      <CommandLine condition="contains">-decode</CommandLine>
    </ProcessCreate>

    <!-- T1140: copy /b -->
    <ProcessCreate onmatch="include">
      <Image condition="image">copy.exe</Image>
      <CommandLine condition="contains">/b</CommandLine>
    </ProcessCreate>

    <!-- T1027: PowerShell encoded command -->
    <ProcessCreate onmatch="include">
      <Image condition="image">powershell.exe</Image>
      <CommandLine condition="contains">-EncodedCommand</CommandLine>
    </ProcessCreate>

    <!-- T1134: runas /user -->
    <ProcessCreate onmatch="include">
      <Image condition="image">runas.exe</Image>
      <CommandLine condition="contains">/user:</CommandLine>
    </ProcessCreate>
  </RuleGroup>
</EventFiltering>