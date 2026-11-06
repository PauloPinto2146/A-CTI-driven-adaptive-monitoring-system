<Sysmon schemaversion="4.30">
   <EventFiltering>
      <!-- IOC: specific malicious filenames -->
      <RuleGroup groupRelation="or">
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wiseman.EXE</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wininet.dll</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- BEHAVIOR: Rundll32 abuse (T1218.011) -->
      <RuleGroup name="technique_id=T1218.011" groupRelation="or">
         <FileCreate onmatch="include">
            <Image condition="end with">rundll32.exe</Image>
            <TargetFilename condition="contains any">.dll;.cpl</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- BEHAVIOR: Certutil deobfuscation (T1140) -->
      <RuleGroup name="technique_id=T1140" groupRelation="or">
         <FileCreate onmatch="include">
            <Image condition="end with">certutil.exe</Image>
            <TargetFilename condition="contains any">.txt;.cer;.enc;.b64;.zip;.sct;.hta</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- BEHAVIOR: PowerShell deobfuscation (T1140) -->
      <RuleGroup name="technique_id=T1140" groupRelation="or">
         <FileCreate onmatch="include">
            <Image condition="end with">powershell.exe</Image>
            <TargetFilename condition="contains any">.ps1;.psm1;.txt;.zip;.enc</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- BEHAVIOR: copy.exe deobfuscation (T1140) -->
      <RuleGroup name="technique_id=T1140" groupRelation="or">
         <FileCreate onmatch="include">
            <Image condition="end with">copy.exe</Image>
            <TargetFilename condition="contains any">.txt;.b64;.enc;.zip</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- DERIVED: Files dropped in common temporary / download / autostart locations -->
      <RuleGroup groupRelation="or">
         <FileCreate onmatch="include">
            <TargetFilename condition="contains any">\AppData\Local\Temp\;\Downloads\;\Startup\</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- DERIVED: Executable dropped in privileged directories related to CVE‑2023‑27350 -->
      <RuleGroup name="cve=CVE-2023-27350" groupRelation="or">
         <FileCreate onmatch="include">
            <TargetFilename condition="begin with">C:\Windows\System32\</TargetFilename>
            <TargetFilename condition="end with">.exe</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="begin with">C:\Program Files\PaperCut</TargetFilename>
            <TargetFilename condition="end with">.exe</TargetFilename>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>