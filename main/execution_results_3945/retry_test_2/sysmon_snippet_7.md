<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="is">wiseman.EXE</ImageLoaded>
          <Hashes condition="is">ebba8f4342b65faccdd2a48be9f2654d3fa523360f17ff68d5498a453f76c205</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">wininet.dll</ImageLoaded>
          <Hashes condition="is">fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c</Hashes>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="end with">.cpl</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <ImageLoaded condition="is any">.cpl;.js;.sct;.hta</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">rundll32.exe</Image>
          <Signed condition="is">false</Signed>
        </Rule>
        <Rule groupRelation="and">
          <Image condition="end with">cmd.exe</Image>
          <Signed condition="is">false</Signed>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>