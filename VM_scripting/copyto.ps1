$VMName      = "WMA_apache_juice_python"
$VMUser      = "paulopinto"
$VMPass      = "haslab"
$VBoxManage  = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

$HostSourceDir = "C:\Users\Paulo\Desktop\Monitorizacao_adaptativa\main\execution_results_9007"
$GuestParent   = "C:\Users\PauloPinto\Desktop\Monitorizacao_adaptativa\main\execution_results_9007"

# Garante que a diretoria-pai existe no guest
& $VBoxManage guestcontrol "$VMName" mkdir `
    --username $VMUser --password $VMPass `
    --parents `
    $GuestParent

# Copia a pasta inteira (conteúdo + subpastas)
& $VBoxManage guestcontrol "$VMName" copyto `
    --username $VMUser --password $VMPass `
    --recursive `
    $HostSourceDir `
    $GuestParent