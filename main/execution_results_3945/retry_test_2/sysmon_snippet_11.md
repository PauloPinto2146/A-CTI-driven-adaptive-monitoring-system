<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">wiseman.EXE</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains">wininet.dll</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">.dll;.cpl;.sct;.hta;.js</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <TargetFilename condition="contains any">.txt;.cer;.enc;.b64;.zip;.7z</TargetFilename>
      </FileCreate>
    </RuleGroup>

    <RuleGroup name="" groupRelation="or">
      <FileCreate onmatch="include">
        <Image condition="image">rundll32.exe</Image>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>