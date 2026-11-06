
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: malicious DLL loaded (wininet.dll) -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="is">C:\Windows\System32\wininet.dll</ImageLoaded>
          <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
        </Rule>
      </ImageLoad>

      <!-- IOC: malicious process image (wiseman.exe) -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="contains">wiseman.exe</Image>
        </Rule>
      </ImageLoad>

      <!-- BEHAVIOR: rundll32.exe loading modules with suspicious extensions -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="contains any">.dll;.cpl;.sct;.hta;.js</ImageLoaded>
        </Rule>
      </ImageLoad>

      <!-- BEHAVIOR: rundll32.exe loading unsigned/invalid‑signed modules -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <Signed condition="is">false</Signed>
        </Rule>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
      </ImageLoad>

      <!-- DERIVED: cmd.exe loading modules from temporary or public directories -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">cmd.exe</Image>
          <ImageLoaded condition="contains any">%TEMP%;C:\Users\Public</ImageLoaded>
        </Rule>
      </ImageLoad>

      <!-- DERIVED: any PaperCut‑related process loading unsigned modules -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="contains">PaperCut</Image>
          <Signed condition="is not">true</Signed>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
