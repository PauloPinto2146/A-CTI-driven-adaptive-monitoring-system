<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <!-- IOC: specific malicious executable -->
        <Rule groupRelation="and">
          <Image condition="is">wiseman.EXE</Image>
          <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
        </Rule>
        <!-- IOC: malicious DLL with known hash -->
        <Rule groupRelation="and">
          <ImageLoaded condition="is">wininet.dll</ImageLoaded>
          <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
        </Rule>
        <!-- BEHAVIOR: rundll32 abuse loading DLL/CPL/JavaScript -->
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="contains any">.dll;.cpl;javascript:</ImageLoaded>
        </Rule>
        <!-- BEHAVIOR: cmd.exe loading any module -->
        <Rule groupRelation="and">
          <Image condition="end with">cmd.exe</Image>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>