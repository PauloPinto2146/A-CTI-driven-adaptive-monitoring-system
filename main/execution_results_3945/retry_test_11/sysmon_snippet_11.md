<Sysmon schemaversion="4.30">
   <EventFiltering>
      <!-- Rundll32 abuse (T1218.011) -->
      <RuleGroup name="technique_id=T1218.011,technique_name=Rundll32" groupRelation="or">
         <FileCreate onmatch="include">
            <Image condition="end with">rundll32.exe</Image>
            <TargetFilename condition="contains any">.dll;.cpl;.sct;.hta</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- Deobfuscation/Decoding utilities (T1140, T1027) -->
      <RuleGroup name="technique_id=T1140,technique_id=T1027" groupRelation="or">
         <FileCreate onmatch="include">
            <Image condition="end with">certutil.exe</Image>
            <TargetFilename condition="contains any">.txt;.cer;.enc;.b64;.zip;.7z</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <Image condition="end with">powershell.exe</Image>
            <TargetFilename condition="contains any">.txt;.cer;.enc;.b64;.zip;.7z</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <Image condition="end with">copy.exe</Image>
            <TargetFilename condition="contains any">.txt;.cer;.enc;.b64;.zip;.7z</TargetFilename>
         </FileCreate>
      </RuleGroup>

      <!-- Indicators of Compromise -->
      <RuleGroup name="ioc_files" groupRelation="or">
         <FileCreate onmatch="include">
            <TargetFilename condition="end with">wiseman.EXE</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="end with">wininet.dll</TargetFilename>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>