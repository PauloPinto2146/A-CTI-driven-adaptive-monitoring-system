<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <!-- IOC: wiseman.exe SHA256 hash -->
        <Rule groupRelation="and">
          <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
        </Rule>
        <!-- IOC: wininet.dll SHA256 hash -->
        <Rule groupRelation="and">
          <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
        </Rule>
        <!-- BEHAVIOR: rundll32.exe loading .cpl files -->
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="end with">.cpl</ImageLoaded>
        </Rule>
        <!-- BEHAVIOR: rundll32.exe loading unsigned modules -->
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <Signed condition="is">false</Signed>
        </Rule>
        <!-- BEHAVIOR: rundll32.exe loading modules with invalid signatures -->
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>