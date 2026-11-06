<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup groupRelation="or">
      <!-- IOC: specific malicious filenames -->
      <FileCreate onmatch="include">
        <TargetFilename condition="is">wiseman.EXE</TargetFilename>
      </FileCreate>
      <FileCreate onmatch="include">
        <TargetFilename condition="is">wininet.dll</TargetFilename>
      </FileCreate>

      <!-- BEHAVIOR: Rundll32‑related payloads dropped in temp or user download folders -->
      <FileCreate onmatch="include">
        <Rule groupRelation="and">
          <TargetFilename condition="ends with">.dll</TargetFilename>
          <TargetFilename condition="contains any">%TEMP%;%USERPROFILE%\Downloads</TargetFilename>
        </Rule>
      </FileCreate>
      <FileCreate onmatch="include">
        <Rule groupRelation="and">
          <TargetFilename condition="ends with">.cpl</TargetFilename>
          <TargetFilename condition="contains any">%TEMP%;%USERPROFILE%\Downloads</TargetFilename>
        </Rule>
      </FileCreate>
      <FileCreate onmatch="include">
        <Rule groupRelation="and">
          <TargetFilename condition="ends with">.sct</TargetFilename>
          <TargetFilename condition="contains any">%TEMP%;%USERPROFILE%\Downloads</TargetFilename>
        </Rule>
      </FileCreate>
      <FileCreate onmatch="include">
        <Rule groupRelation="and">
          <TargetFilename condition="ends with">.hta</TargetFilename>
          <TargetFilename condition="contains any">%TEMP%;%USERPROFILE%\Downloads</TargetFilename>
        </Rule>
      </FileCreate>
      <FileCreate onmatch="include">
        <Rule groupRelation="and">
          <TargetFilename condition="ends with">.js</TargetFilename>
          <TargetFilename condition="contains any">%TEMP%;%USERPROFILE%\Downloads</TargetFilename>
        </Rule>
      </FileCreate>

      <!-- BEHAVIOR: Deobfuscation/decoding file types (T1140) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">.txt;.cer;.enc;.b64;.zip</TargetFilename>
      </FileCreate>

      <!-- BEHAVIOR: Obfuscated/compressed payloads (T1027) -->
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">.zip;.7z;.enc</TargetFilename>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>