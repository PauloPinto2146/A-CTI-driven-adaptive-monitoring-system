<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wiseman.EXE -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">wiseman.EXE</TargetFilename>
      </FileCreate>

      <!-- IOC: wininet.dll -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">wininet.dll</TargetFilename>
      </FileCreate>

      <!-- BEHAVIOR: rundll32.exe creating DLL/CPL/SCT/HTA files -->
      <FileCreate onmatch="include">
        <Image condition="image">rundll32.exe</Image>
        <TargetFilename condition="contains any">.dll;.cpl;.sct;.hta</TargetFilename>
      </FileCreate>

      <!-- BEHAVIOR: certutil.exe creating .cer files -->
      <FileCreate onmatch="include">
        <Image condition="image">certutil.exe</Image>
        <TargetFilename condition="end with">.cer</TargetFilename>
      </FileCreate>

      <!-- BEHAVIOR: powershell.exe creating .b64 files -->
      <FileCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <TargetFilename condition="end with">.b64</TargetFilename>
      </FileCreate>

      <!-- BEHAVIOR: powershell.exe creating .zip files -->
      <FileCreate onmatch="include">
        <Image condition="image">powershell.exe</Image>
        <TargetFilename condition="end with">.zip</TargetFilename>
      </FileCreate>

      <!-- BEHAVIOR: copy.exe creating .txt files -->
      <FileCreate onmatch="include">
        <Image condition="image">copy.exe</Image>
        <TargetFilename condition="end with">.txt</TargetFilename>
      </FileCreate>

      <!-- DERIVED: monitoring any DLL creation (CVE‑2023‑27350 relevance) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="end with">.dll</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>