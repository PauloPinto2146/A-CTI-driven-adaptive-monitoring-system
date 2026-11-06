<Sysmon schemaversion="4.30">
  <EventFiltering>
    <!-- Include suspicious driver loads -->
    <RuleGroup name="" groupRelation="or">
      <DriverLoad>
        <!-- Drivers loaded from typical user‑writable locations -->
        <Rule groupRelation="or">
          <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
        </Rule>
        <Rule groupRelation="or">
          <ImageLoaded condition="begin with">C:\Temp\</ImageLoaded>
        </Rule>

        <!-- Drivers that are unsigned or have an invalid/unknown signature -->
        <Rule groupRelation="or">
          <Signed condition="is">false</Signed>
        </Rule>
        <Rule groupRelation="or">
          <SignatureStatus condition="is not">Valid</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>

    <!-- Exclude well‑known benign Microsoft drivers with a valid signature -->
    <RuleGroup name="" groupRelation="or">
      <DriverLoad onmatch="exclude">
        <Rule groupRelation="and">
          <Signature condition="contains">Microsoft</Signature>
          <SignatureStatus condition="is">Valid</SignatureStatus>
        </Rule>
      </DriverLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>