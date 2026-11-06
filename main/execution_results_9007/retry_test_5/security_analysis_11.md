[IOC] Monitor any process creating file named 'x86_64-unknown-linux-esxi.elf' | Source: filename:x86_64-unknown-linux-esxi.elf  
[IOC] Monitor any process creating file named 'h3odp7l2u.exe' | Source: filename:h3odp7l2u.exe  
[IOC] Monitor any process creating file named 'hi9lezv.exe' | Source: filename:hi9lezv.exe  
[IOC] Monitor any process creating file named '072wiof7.exe' | Source: filename:072wiof7.exe  
[IOC] Monitor any process creating file named 'k0d649u.exe' | Source: filename:k0d649u.exe  
[IOC] Monitor any process creating file named '2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat' | Source: filename:2026-03-08_ec37a6c4866b7324fce2f11b0e89c4c2_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Monitor any process creating file named '2qfguc.exe' | Source: filename:2qfguc.exe  
[IOC] Monitor any process creating file named '7hhel.exe' | Source: filename:7hhel.exe  
[IOC] Monitor any process creating file named '3ctjhm3.exe' | Source: filename:3ctjhm3.exe  
[IOC] Monitor any process creating file named '2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat' | Source: filename:2026-04-08_78d359a87ae75ece08976e8b14d877fe_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Monitor any process creating file named 'bjiw49.exe' | Source: filename:bjiw49.exe  
[IOC] Monitor any process creating file named '7l73h.exe' | Source: filename:7l73h.exe  
[IOC] Monitor any process creating file named '2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat' | Source: filename:2026-04-11_a9bc032353bd246ba50af1b8d4849bfd_akira_cobalt-strike_glassworm_poet-rat  
[IOC] Monitor any process creating file named '0m6m882x2.exe' | Source: filename:0m6m882x2.exe  
[IOC] Monitor any process creating file named 'inc.exe' | Source: filename:inc.exe  
[IOC] Monitor any process creating file named '61pd6n3t.exe' | Source: filename:61pd6n3t.exe  
[IOC] Monitor any process creating file named 'mk1yd.exe' | Source: filename:mk1yd.exe  
[IOC] Monitor any process creating file named 'a3mnw9.exe' | Source: filename:a3mnw9.exe  
[IOC] Monitor any process creating file named 'win.bin' | Source: filename:win.bin  
[IOC] Monitor any process creating file named 'vw06lg0y.exe' | Source: filename:vw06lg0y.exe  
[IOC] Monitor any process creating file named 'qgp2s6z.exe' | Source: filename:qgp2s6z.exe  
[IOC] Monitor any process creating file named 'tt24n8xsl.exe' | Source: filename:tt24n8xsl.exe  

[BEHAVIOR] Monitor creation of executable files (.exe, .dll, .bin) in user %TEMP% or %TMP% directories | Source: T1567  
[BEHAVIOR] Monitor creation of executable files in users' Downloads folders (e.g., %USERPROFILE%\Downloads) | Source: T1566  
[BEHAVIOR] Monitor creation of files with uncommon or newly generated extensions (e.g., .encrypted, .locked) in user document directories at a high rate | Source: T1486  
[BEHAVIOR] Monitor creation of files in system service locations (e.g., %SystemRoot%\System32) by processes that are not known service installers | Source: T1219