<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wiseman.EXE</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="is">wininet.dll</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="contains any">.cpl;.dll;.js;.sct;.hta;.txt;.cer;.enc;.b64;.zip;.7z</TargetFilename>
         </FileCreate>
         <FileCreate onmatch="include">
            <TargetFilename condition="contains">\Temp\</TargetFilename>
         </FileCreate>
      </RuleGroup>
   </EventFiltering>
</Sysmon>