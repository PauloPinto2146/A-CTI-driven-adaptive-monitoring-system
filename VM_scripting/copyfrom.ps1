$VMName = "VM_NET"
$VMUser = "paulopinto"
$VMPass = "haslab"
$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# $GuestSourceDir = "C:\Users\PauloPinto\Desktop\info"
$GuestSourceDir = "home/paulopinto/service.log"
$HostDestDir    = "C:\Users\Paulo\Desktop\servicelogs.txt"

New-Item -ItemType Directory -Force $HostDestDir | Out-Null

& $VBoxManage guestcontrol "$VMName" copyfrom `
    --username $VMUser --password $VMPass `
    --recursive `
    $GuestSourceDir `
    $HostDestDir