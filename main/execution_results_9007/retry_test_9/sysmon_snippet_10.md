<Sysmon schemaversion="4.60">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and">
          <SourceImage condition="image">h3odp7l2u.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">hi9lezv.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">072wiof7.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">k0d649u.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">2qfguc.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">7hhel.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">3ctjhm3.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">bjiw49.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">7l73h.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">0m6m882x2.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">inc.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">61pd6n3t.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">mk1yd.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">a3mnw9.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">vw06lg0y.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">qgp2s6z.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
        <Rule groupRelation="and">
          <SourceImage condition="image">tt24n8xsl.exe</SourceImage>
          <TargetImage condition="image">lsass.exe</TargetImage>
          <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>