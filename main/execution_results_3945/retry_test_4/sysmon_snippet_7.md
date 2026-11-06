<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <!-- IOC: wininet.dll -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
        </Rule>
      </ImageLoad>

      <!-- IOC: wiseman.EXE -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
        </Rule>
      </ImageLoad>

      <!-- BEHAVIOR: rundll32.exe loading .cpl files -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="end with">.cpl</ImageLoaded>
        </Rule>
      </ImageLoad>

      <!-- BEHAVIOR: rundll32.exe loading any DLL (atypical) -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="end with">.dll</ImageLoaded>
        </Rule>
      </ImageLoad>

      <!-- BEHAVIOR: rundll32.exe loading script protocols or script files -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="contains">javascript:</ImageLoaded>
        </Rule>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="contains">mshtml</ImageLoaded>
        </Rule>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="end with">.sct</ImageLoaded>
        </Rule>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="end with">.hta</ImageLoaded>
        </Rule>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="end with">.js</ImageLoaded>
        </Rule>
      </ImageLoad>

      <!-- BEHAVIOR: cmd.exe loading files from temporary or public locations -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">cmd.exe</Image>
          <ImageLoaded condition="contains any">%TEMP%;C:\Users\Public</ImageLoaded>
        </Rule>
      </ImageLoad>

      <!-- BEHAVIOR: cmd.exe loading unsigned or improperly signed modules -->
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">cmd.exe</Image>
          <Signed condition="is">false</Signed>
        </Rule>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">cmd.exe</Image>
          <SignatureStatus condition="is">invalid</SignatureStatus>
        </Rule>
      </ImageLoad>
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="end with">cmd.exe</Image>
          <SignatureStatus condition="is">missing</SignatureStatus>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>