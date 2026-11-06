<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup groupRelation="or">
         <!-- IOC: Specific malicious filenames -->
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wiseman.EXE</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wininet.dll</TargetFilename>
         </FileCreate>

         <!-- BEHAVIOR: Rundll32 abuse with typical payload extensions -->
         <FileCreate onmatch="include">
            <Image condition="image">rundll32.exe</Image>
            <TargetFilename condition="end with">.dll</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <Image condition="image">rundll32.exe</Image>
            <TargetFilename condition="end with">.cpl</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <Image condition="image">rundll32.exe</Image>
            <TargetFilename condition="end with">.sct</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <Image condition="image">rundll32.exe</Image>
            <TargetFilename condition="end with">.hta</TargetFilename>
         </FileCreate>

         <!-- BEHAVIOR: Creation of files commonly used for decoding/obfuscation -->
         <FileCreate onmatch="include">
            <TargetFilename condition="contains any">.txt;.cer;.b64;.zip;.7z;.enc</TargetFilename>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>