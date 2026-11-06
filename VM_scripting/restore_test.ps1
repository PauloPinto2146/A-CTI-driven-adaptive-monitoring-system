$VMName = "WMA_apache_juice_python"
$VMUser = "PauloPinto"
$VMPass = "haslab"
$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$SnapshotName = "Pre-malware"


& $VBoxManage snapshot "$VMName" restore $SnapshotName