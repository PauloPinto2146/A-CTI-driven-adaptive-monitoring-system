<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="include">
        <Rule groupRelation="and">
          <Image condition="contains any">\Users\;Temp\;AppData\</Image>
          <Image condition="end with">.sys</Image>
        </Rule>
      </DriverLoad>
      <DriverLoad onmatch="include">
        <Rule groupRelation="or">
          <Signed condition="is">false</Signed>
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>