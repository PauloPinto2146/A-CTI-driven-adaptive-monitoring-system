<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <Rule groupRelation="or">
          <Signed condition="is">false</Signed>
        </Rule>
        <Rule groupRelation="or">
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
        <Rule groupRelation="or">
          <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
        </Rule>
        <Rule groupRelation="or">
          <ImageLoaded condition="begin with">C:\Temp\</ImageLoaded>
        </Rule>
        <Rule groupRelation="or">
          <ImageLoaded condition="contains any">svhostx;winhelp</ImageLoaded>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>