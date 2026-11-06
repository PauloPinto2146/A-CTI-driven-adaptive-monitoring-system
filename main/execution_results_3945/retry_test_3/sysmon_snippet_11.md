<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup groupRelation="or">
      <FileCreate onmatch="include">
        <Rule groupRelation="and">
          <TargetFilename condition="is">wiseman.EXE</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <TargetFilename condition="is">wininet.dll</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <TargetFilename condition="end with">.dll</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <TargetFilename condition="end with">.cpl</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">rundll32.exe</Image>
          <TargetFilename condition="contains any">.js;.sct;.hta</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">certutil.exe</Image>
          <TargetFilename condition="contains any">.cer;.b64;.enc;.txt;.zip;.7z</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">powershell.exe</Image>
          <TargetFilename condition="contains any">.b64;.enc;.txt;.zip;.7z</TargetFilename>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="image">copy.exe</Image>
          <TargetFilename condition="contains any">.b64;.enc;.txt;.zip;.7z</TargetFilename>
        </Rule>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>