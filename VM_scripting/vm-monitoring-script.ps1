# =========================================================================
# 1. Start the VM and let it cool down
# =========================================================================

# Name of your Virtual Machine
$VMName = "WMA_apache_juice_python"
$VMUser = "PauloPinto"
$VMPass = "haslab"
$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
$CommandLine = "C:\Windows\System32\cmd.exe"
$SnapshotName = "MalwareState" #MalwareState

$CleanDirectoryCommand = "curl -X DELETE http://127.0.0.1:8000/clean"

$i = 1
$initial_i = $i
$final_i = 10

function Reset-VM {
    $script:vmStarted = $false
    if (& $VBoxManage showvminfo "$VMName" --machinereadable | Select-String 'VMState="(running|paused)"') {
        & $VBoxManage controlvm "$VMName" poweroff | Out-Null
    }
    for ($t = 0; $t -lt 12; $t++) {
        if (& $VBoxManage showvminfo "$VMName" --machinereadable | Select-String 'VMState="(poweroff|aborted|saved)"') { break }
        Start-Sleep -Seconds 5
    }
    Start-Sleep -Seconds 5
    $restored = $false
    for ($r = 0; $r -lt 3; $r++) {

        & $VBoxManage snapshot "$VMName" restore $SnapshotName
        if ($LASTEXITCODE -eq 0) { $restored = $true; break }
        Start-Sleep -Seconds 10
    }
    if (-not $restored) { return }
    for ($a = 0; $a -lt 6; $a++) {
        & $VBoxManage startvm "$VMName" --type gui
        if ($LASTEXITCODE -eq 0) { $script:vmStarted = $true; break }
        Start-Sleep -Seconds 10
    }
}

$failures = 0; $maxFailures = 5

while ($i -le $final_i){
    if ($failures -ge $maxFailures) { Write-Host "Too many failures, aborting" -ForegroundColor Red; break }

    $currentRun = $i
    $runOk = $false; $mock_ipapi_ready = $false; $cti_app_ready = $false

    Write-Host "Restoring live snapshot for execution $i..." -ForegroundColor Cyan
    Reset-VM

    if (-not $vmStarted) { $failures++; continue }

    $vm_init_tries = 0
    $max_vm_init_tries = 12

    # Waiting for VBoxService initialization<
    while ($vm_init_tries -lt $max_vm_init_tries) {
        $out = & $VBoxManage guestcontrol "$VMName" run --username $VMUser --password $VMPass --exe "C:\Windows\System32\hostname.exe" 2>&1
        if ($LASTEXITCODE -eq 0) { break }
        Write-Host "VBoxService not ready ($vm_init_tries/$max_vm_init_tries): $out" -ForegroundColor Yellow
        Start-Sleep -Seconds 5
        $vm_init_tries++
    }


    if ($vm_init_tries -lt $max_vm_init_tries){
        # Cooldown time
        Write-Host "60 second cooldown time..."
        Start-Sleep -Seconds 60
        # =========================================================================
        # 2. Start the application, running the two servers
        # =========================================================================

        Write-Host "Starting mock-api server..." -ForegroundColor Cyan

        $mock_ipapi_path = "C:\Users\PauloPinto\Desktop\Monitorizacao_adaptativa\App\mock-ip-api"
        $run_mock_ipapi_command = "uv run --directory $mock_ipapi_path python -m uvicorn app.main:app --host 0.0.0.0 --port 9000"

        # Executes mock ip-api server
        & $VBoxManage guestcontrol "$VMName" start `
            --username $VMUser `
            --password $VMPass `
            --exe $CommandLine -- /c $run_mock_ipapi_command

        # Make sure the mock-ip-api server is ready
        Write-Host "Veryfing if mock ip-api is ready..." -ForegroundColor Cyan
        $mock_ipapi_ready = $false
        $maxTries = 10
        $tries = 0

        while (-not $mock_ipapi_ready -and $tries -lt $maxTries) {

            $tempOut = "C:\Users\$VMUser\check_status.txt"

            # Runs curl in VM to get 200ok result
            & $VBoxManage guestcontrol "$VMName" run `
                --username $VMUser --password $VMPass `
                --exe $CommandLine -- /c "curl.exe -GET http://localhost:9000/check > $tempOut 2>&1"

            Start-Sleep -Seconds 2

            $statusRaw = & $VBoxManage guestcontrol "$VMName" run `
                --username $VMUser --password $VMPass `
                --exe $CommandLine -- /c "type $tempOut" 2>$null

            Write-Host "Response obtained: '$statusRaw'" -ForegroundColor DarkGray

            if ($statusRaw -match "200") {
                $mock_ipapi_ready = $true
                Write-Host "Mock-ip-api is ready!" -ForegroundColor Green
            } else {
                Write-Host "Still trying to detect if mock-ip-api server is up... ($tries/$maxTries)" -ForegroundColor Yellow
                Start-Sleep -Seconds 10
                $tries++
            }
        }

        if (-not $mock_ipapi_ready) {
            Write-Host "WARNING: Timout reached! mock_ipapi server was not ready. Restarting" -ForegroundColor Red
        }

        if ($mock_ipapi_ready){
            $cti_app_path = "C:\Users\PauloPinto\Desktop\Monitorizacao_adaptativa\App\application-for-sysmon"
            $run_cti_app_command = "uv run --directory $cti_app_path python -m uvicorn app.main:app --host 0.0.0.0 --port 8000"

            # Executes cti app server
            & $VBoxManage guestcontrol "$VMName" start `
                --username $VMUser `
                --password $VMPass `
                --exe $CommandLine -- /c $run_cti_app_command

            # Make sure the cti app server is ready
            Write-Host "Veryfing if cti app is ready..." -ForegroundColor Cyan
            $cti_app_ready = $false
            $maxTries = 10
            $tries = 0

            while (-not $cti_app_ready -and $tries -lt $maxTries) {

                $tempOut = "C:\Users\$VMUser\check_status.txt"

                # Runs curl in VM to get 200ok result
                & $VBoxManage guestcontrol "$VMName" run `
                    --username $VMUser --password $VMPass `
                    --exe $CommandLine -- /c "curl.exe -X GET http://localhost:8000/check > $tempOut 2>&1"

                Start-Sleep -Seconds 2

                $statusRaw = & $VBoxManage guestcontrol "$VMName" run `
                    --username $VMUser --password $VMPass `
                    --exe $CommandLine -- /c "type $tempOut" 2>$null

                Write-Host "Response obtained: '$statusRaw'" -ForegroundColor DarkGray

                if ($statusRaw -match "200") {
                    $cti_app_ready = $true
                    Write-Host "Cti app is ready!" -ForegroundColor Green
                } else {
                    Write-Host "Still trying to detect if cti app is up... ($tries/$maxTries)" -ForegroundColor Yellow
                    Start-Sleep -Seconds 10
                    $tries++
                }
            }

            if (-not $cti_app_ready) {
                Write-Host "WARNING: Timout reached! cti app server was not ready. Restarting" -ForegroundColor Red
            } 
        }   

        if ($mock_ipapi_ready -and $cti_app_ready){
            # =========================================================================
            # 3. Start the apache jmeter and run the traffic simulation 
            # =========================================================================
            $MonitoringOption = "MISP" # All / Nothing / Default / MISP
            $MISP_ID = 9007

            $TrafficN = 0

            $JMeterBatch = "C:\apache-jmeter-5.6.3\bin\jmeter.bat"
            $JMXTemplate  = "C:\Users\PauloPinto\Desktop\Monitorizacao_adaptativa\main\apache_tamplates\traffic$TrafficN.jmx"

            $TargetDir = "C:\Users\PauloPinto\Desktop\$MonitoringOption\run$i"


            $JMeterCmd = "$JMeterBatch -n -t $JMXTemplate > C:\Users\$VMUser\jmeter_stdout.txt 2>&1"

            Write-Host "Starting JMeter traffic simulation in background..." -ForegroundColor Cyan
            $status_apachejmeter = & $VBoxManage guestcontrol "$VMName" start `
                --username $VMUser `
                --password $VMPass `
                --cwd "C:\apache-jmeter-5.6.3\bin" `
                --exe $CommandLine -- /c $JMeterCmd 2>&1

            Write-Host "Exit code: $LASTEXITCODE" -ForegroundColor Yellow
            Write-Host "Response obtained from apache jmeter: '$status_apachejmeter'" -ForegroundColor Yellow

            & $VBoxManage guestcontrol "$VMName" run `
                --username $VMUser --password $VMPass `
                --exe $CommandLine -- /c "tasklist | findstr java > C:\Users\$VMUser\java_check.txt 2>&1"

            & $VBoxManage guestcontrol "$VMName" run `
                --username $VMUser --password $VMPass `
                --exe $CommandLine -- /c "type C:\Users\$VMUser\java_check.txt"

            # =========================================================================
            # 4. Run the monitoring system with the desired configuration
            # =========================================================================

            # Monitoring test parameters
            $Seconds = 600
            $ResTag = "run" + $i + "_" 

            # Malware samples: 
            #   - fda9864b1aa230b60d0c736559415ac9c79e240cce411daed5da2facb9ced87c.exe
            #   - 2026-01-26_10d6e04270806d8547a5a03a912a5dd9_akira_cobalt-strike_glassworm_poet-rat
            
            $Malware_exe_path = "C:\Users\PauloPinto\Desktop\2026-01-26_10d6e04270806d8547a5a03a912a5dd9_akira_cobalt-strike_glassworm_poet-rat" 

            $MainPATH = "C:\Users\PauloPinto\Desktop\Monitorizacao_adaptativa\main"
            $Command = "python main.py $Seconds $MonitoringOption $MISP_ID $Malware_exe_path $TargetDir $ResTag"  

            Write-Host "Starting monitoring process for $Seconds seconds" -ForegroundColor Cyan
            & $VBoxManage guestcontrol "$VMName" run --username $VMUser --password $VMPass --cwd $MainPATH --exe $CommandLine -- /c $Command 2>&1 | Tee-Object -Variable output

            $textError = $output | Out-String

            if ($LASTEXITCODE -ne 0 -or $textError -match "Error starting guest session") {
                Write-Host "Failure detected!" -ForegroundColor Red
                Write-Host "Error captures: $textError" -ForegroundColor Yellow
            } else {
                Write-Host "Process concluded with success!" -ForegroundColor Green
                $runOk = $true
                $i = $i + 1
            }
            Start-Sleep -Seconds 15
            & $VBoxManage guestcontrol "$VMName" run --username $VMUser --password $VMPass `
                --exe $CommandLine -- /c "powershell -NoProfile -Command Get-Content C:\Users\$VMUser\jmeter_stdout.txt -Tail 5"

            # =========================================================================
            # 5. Shutdown services and end
            # =========================================================================

            # Graceful shutdown of the apache jmeter
            Write-Host "Stopping JMeter gracefully..." -ForegroundColor Yellow
            & $VBoxManage guestcontrol "$VMName" start `
                --username $VMUser `
                --password $VMPass `
                --exe $CommandLine -- /c "C:\apache-jmeter-5.6.3\bin\shutdown.cmd"

            Write-Host "Waiting for 30 seconds to let JMeter shut down..." -ForegroundColor Yellow
            Start-Sleep -Seconds 30
        } 

        Write-Host "Cleaning the server's storage"
        & $VBoxManage guestcontrol "$VMName" run `
            --username $VMUser --password $VMPass `
            --exe $CommandLine -- /c "curl.exe -X DELETE http://localhost:8000/clean"

        Start-Sleep -Seconds 5

        # Copy results from VM to local machine
        $GuestSourceDir = $TargetDir
        if ($runOk) {
            $HostDestDir = "C:\Users\Paulo\Desktop\monitoring_results\Gh0st_RAT\9007(2)" #\$MISP_ID / $MonitoringOption\traffic$TrafficN\run$currentRun
            New-Item -ItemType Directory -Force $HostDestDir | Out-Null

            & $VBoxManage guestcontrol "$VMName" copyfrom `
            --username $VMUser --password $VMPass `
            --recursive $TargetDir $HostDestDir

            if ($LASTEXITCODE -ne 0) {
                Write-Host "COPY FAILED - stopping so the results stay in the VM ($TargetDir)" -ForegroundColor Red
                break
            }
        }
        if ($runOk) {
            $failures = 0
            Write-Host "Run $currentRun completed!" -ForegroundColor Green
        } else {
            $failures++
            Write-Host "Run $currentRun FAILED (consecutive failures: $failures/$maxFailures)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "VBoxService never became ready, retrying" -ForegroundColor Red
    }

}

Write-Host "All runs ($initial_i to $final_i) completed successfully!" -ForegroundColor Green
& $VBoxManage controlvm "$VMName" poweroff | Out-Null