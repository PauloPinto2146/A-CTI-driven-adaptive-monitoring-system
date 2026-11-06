
<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="T1190_IoC_ImageLoads" groupRelation="or">
      <ImageLoad onmatch="include">
        <Rule groupRelation="and">
          <ImageLoaded condition="is">x86_64-unknown-linux-esxi.elf</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">h3odp7l2u.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">hi9lezv.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">072wiof7.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">k0d649u.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">2qfguc.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">7hhel.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">3ctjhm3.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">bjiw49.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">7l73h.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">0m6m882x2.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">inc.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">61pd6n3t.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">mk1yd.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">a3mnw9.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">win.bin</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">vw06lg0y.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">qgp2s6z.exe</ImageLoaded>
        </Rule>
        <Rule groupRelation="and">
          <ImageLoaded condition="is">tt24n8xsl.exe</ImageLoaded>
        </Rule>
      </ImageLoad>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
