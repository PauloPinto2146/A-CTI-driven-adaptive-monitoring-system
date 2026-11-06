<Sysmon schemaversion="4.30">
	<EventFiltering>
		<RuleGroup name="" groupRelation="or">
			<DnsQuery onmatch="include">
				<Image condition="end with">x86_64-unknown-linux-esxi.elf</Image>
				<Image condition="end with">h3odp7l2u.exe</Image>
				<Image condition="end with">hi9lezv.exe</Image>
				<Image condition="end with">072wiof7.exe</Image>
				<Image condition="end with">k0d649u.exe</Image>
				<Image condition="end with">2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat</Image>
				<Image condition="end with">2qfguc.exe</Image>
				<Image condition="end with">7hhel.exe</Image>
				<Image condition="end with">3ctjhm3.exe</Image>
				<Image condition="end with">2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat</Image>
				<Image condition="end with">bjiw49.exe</Image>
				<Image condition="end with">7l73h.exe</Image>
				<Image condition="end with">2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat</Image>
				<Image condition="end with">0m6m882x2.exe</Image>
				<Image condition="end with">inc.exe</Image>
				<Image condition="end with">61pd6n3t.exe</Image>
				<Image condition="end with">mk1yd.exe</Image>
				<Image condition="end with">a3mnw9.exe</Image>
				<Image condition="end with">win.bin</Image>
				<Image condition="end with">vw06lg0y.exe</Image>
				<Image condition="end with">qgp2s6z.exe</Image>
				<Image condition="end with">tt24n8xsl.exe</Image>
				<QueryName condition="is">incblog.su</QueryName>
				<QueryName condition="is">incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad.onion</QueryName>
				<QueryName condition="is">incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid.onion</QueryName>
			</DnsQuery>
		</RuleGroup>
	</EventFiltering>
</Sysmon>