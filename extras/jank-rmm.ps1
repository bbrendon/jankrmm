
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Option
)


 
Function Invoke-Delete-Old-Logs {

    $currentDate = Get-Date

    # Calculate the date 60 days ago
    $cutOffDate = $currentDate.AddDays(-60)

    # Get files in the directory
    $files = Get-Item -Path C:\PowerShell_transcript*

    # Iterate through each file
    foreach ($file in $files) {
        # Check file's creation date
        if ($file.CreationTime -lt $cutOffDate) {
            Remove-Item $file.FullName -Force
        }
    }


}

Function Invoke-Check-BitLocker-Enabled {

    # Initialize a variable to track BitLocker status
    # $allBitlockerEnabled = $true

    # Check BitLocker status for each volume
    foreach ($volume in Get-BitLockerVolume) {
        # skip volumnes without drive letters. These are usually recovery partitions.
        if ($volume.MountPoint -match '^\\\\\?\\Volume') { continue }
        
        # $volumeStatus = Get-BitLockerVolume -MountPoint $volume.MountPoint | Select-Object -ExpandProperty VolumeStatus
        $volumeStatus = $volume | Select-Object -ExpandProperty  volumestatus
        $ProtectionStatus = $volume | Select-Object -ExpandProperty  ProtectionStatus
        # Check if BitLocker is enabled for the volume
        if (($volumeStatus -ne 'FullyEncrypted') -or ($ProtectionStatus -ne 'On')) {
            Write-Output "ERROR: Volume $($volume.MountPoint) does not have BitLocker enabled."
            # $allBitlockerEnabled = $false
        }
    }

}



function Invoke-Check-Install-Required-Software {

    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
	
    # Google Drive
    $installedApps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Google Drive*" }
	
    if (-not $installedApps) {
        Write-Output "Google Drive is not installed on this system. Installing."
        & "$env:ChocolateyInstall\bin\choco.exe" install googledrive -y --no-progress
        # } else {
        # Write-Output "Google Drive is installed on this system."
        # $installedApps | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate       
    }

    ## OpenVPN
    $installedApps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*OpenVPN*" }
	
    if (-not $installedApps) {
        Write-Output "INFO: OpenVPN is not installed on this system. Installing."
        & "$env:ChocolateyInstall\bin\choco.exe" install openvpn -y --no-progress
    }   

    ## Google Chrome
    $installedApps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Google Chrome*" }
	
    if (-not $installedApps) {
        Write-Output "INFO: Google Chrome is not installed on this system. Installing."
        & "$env:ChocolateyInstall\bin\choco.exe" install googlechrome -y --no-progress
    }        

    ## PDF Reader
    $installedAcrobat = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Acrobat*" }

    $installedSumatra = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*SumatraPDF*" }

    if (-not $installedAcrobat -and -not $installedSumatra) {
        Write-Output "INFO: Neither Adobe Acrobat nor SumatraPDF is installed on this system. Installing SumatraPDF."
        & "$env:ChocolateyInstall\bin\choco.exe" install sumatrapdf.install --params="'/WithPreview /WithFilter'" -y --no-progress
    }

    ## Slack
    $installedApps = Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*slack*" }
	
    if (-not $installedApps) {
        Write-Output "INFO: Slack is not installed on this system. Installing."
        & "$env:ChocolateyInstall\bin\choco.exe" install slack -y --no-progress
    }    

    
}



function Install-Windows-Defender {


    # delete the first iteration of the defender scheduled task. No longer used.
    Unregister-ScheduledTask -TaskName "DefenderCheckNotify" -Confirm:$false -ErrorAction SilentlyContinue

    $scriptPath = "C:\windows\defender-push.ps1"

    # always download the latest script.
    curl.exe -so $scriptPath https://x.x.com/defender-push.ps1

    ## Create Scheudled task that calls the script below. 
    
    $taskName = "DefenderPush"
    
    # Check if the scheduled task exists
    $taskExists = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

    if (-not $taskExists) {
        Write-Output "Scheduled task '$taskName' does not exist. Creating..."

        # Create a new trigger for the scheduled task (every 5 minutes)
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
        #-RepetitionDuration (New-TimeSpan -Days 31)

        # Create the action to run the PowerShell script
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""

        # Register the scheduled task
        Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -User "SYSTEM" -RunLevel Highest -Force

        # Write-Output "Scheduled task '$taskName' created successfully."

    }  

    # Install windows application guard
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard
    if ($feature.State -ne 'Enabled') {
        Write-Output "Enabling Windows Defender Application Guard..."
        Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart
    } else {
        Write-Output "Windows Defender Application Guard is already enabled."
    }

    # Reg settings from the excel spreadsheet
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection" /v DisallowExploitProtectionOverride /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\AppHVSI\AllowAppHVSI_ProviderSet" /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverride /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverride /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v PreventOverrideAppRepUnknown /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Account protection" /v UILockdown /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Device performance and health" /v UILockdown /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Family options" /v UILockdown /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender" /v PUAProtection /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v EnableFileHashComputation /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v MpBafsExtendedTimeout /t REG_DWORD /d 10 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 2 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v DisableEmailScanning /t REG_DWORD /d 0 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v LowCpuPriority /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v DisableBlockAtFirstSeen /t REG_DWORD /d 0 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v EnableControlledFolderAccess /t REG_DWORD /d 0 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v EnableNetworkProtection /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f    ; reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_DWORD /d 0 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v CaptureThreatWindow /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v NotifyMalicious /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v NotifyPasswordReuse /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v NotifyUnsafeApp /t REG_DWORD /d 1 /f
    reg.exe add "HKLM\Software\Policies\Microsoft\Windows\WTDS\Components" /v ServiceEnabled /t REG_DWORD /d 1 /f
    


    ##### ASR RULES BEGIN -  NOT IN EXCEL SHEET  #############################
    REG.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v ExploitGuard_ASR_Rules /t REG_DWORD /d 1 /f
    REG.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" /v ExploitGuard_ASR_ASROnlyExclusions /t REG_DWORD /d 1 /f
    REG.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions" /v "C:\Program Files\TacticalAgent\tacticalrmm.exe" /t REG_SZ /d 0 /f
    REG.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions" /v "C:\Windows\System32\lsass.exe" /t REG_SZ /d 0 /f

    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 56a863a9-875e-4185-98a7-b882c64b5ce5 /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v d4f940ab-401b-4efc-aadc-ad5f3c50688a /t REG_SZ /d 1 /f
    
    # This triggered. Disable for now.
    # reg.exe ADD  "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 /t REG_SZ /d 1 /f
    reg.exe DELETE "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 /f

    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 /t REG_SZ /d 1 /f
    #  reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 01443614-cd74-433a-b99e-2ecdc07bfc25 /t REG_SZ /d 1 /f
    reg.exe DELETE "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 01443614-cd74-433a-b99e-2ecdc07bfc25 /f
    
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 5beb7efe-fd9a-4556-801d-275e5ffc04cc /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v d3e037e1-3eb8-44c8-a917-57927947596d /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 3b576869-a4ec-4529-8536-b80a7769e899 /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 26190899-1602-49e8-8b27-eb1d0a1ce869 /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v e6db77e5-3df2-4cf1-b95a-636979351e5b /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v d1e49aac-8f56-4280-b9ba-993a6d77406c /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 33ddedf1-c6e0-47cb-833e-de6133960387 /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 /t REG_SZ /d 1 /f
    
    # reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb /t REG_SZ /d 1 /f
    reg.exe DELETE "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb /f
    
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v a8f5898e-1dc8-49a9-9878-85004b8a61e6 /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b /t REG_SZ /d 1 /f
    reg.exe ADD "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" /v c1db55ab-c21a-4637-bb3f-a12568109d35 /t REG_SZ /d 1 /f


    ###### ASR RULES END #################
  
}
 
function Invoke-Check-Defender {
    # This checks the status of Windows Defender and verifies that it is operating correctly.

    # Get specific status information from Windows Defender and verify their values
    $status_is_false = Get-MpComputerStatus | Select-Object DefenderSignaturesOutOfDate, FullScanOverdue, FullScanRequired, QuickScanOverdue

    # Check if all values are False
    $allFalse = $status_is_false.PSObject.Properties.Value -notcontains $true


    $status_is_true = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected, NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled

    # Check if all values are True
    $allTrue = $status_is_true.PSObject.Properties.Value -notcontains $false

    if (($allTrue -eq $False) -or ($allFalse -eq $False)) {
        Write-Output "ERROR: Defender is not configured correctly."
        Get-MpComputerStatus
    }  

}
  
function Send-ComputerInfoToAPI {
   

    $os = Get-WmiObject -Class Win32_OperatingSystem


    $url = "https://x.x.com/api1/"
    
    # Define the headers
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    $body = @{
        key          = 'ffa2323b'
        serial       = (Get-WmiObject -Class Win32_BIOS).SerialNumber
        hostname     = ($env:COMPUTERNAME).tolower()
        ip_public    = Invoke-RestMethod -Uri "http://ipv4.icanhazip.com"
        ip           = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '127*' } | Select-Object -First 1 -ExpandProperty IPAddress)
        processor    = (Get-WmiObject -Class Win32_Processor).Name -replace "Intel\(R\) Core\(TM\)", "Core" -replace " with Radeon Graphics", "" -replace "AMD ", ""
        ram          = [math]::round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
        storage      = [math]::round((Get-Volume -DriveLetter C).Size / 1GB , 1)
        os_version   = "$($os.Caption) $($os.BuildNumber)" -replace "Microsoft Windows", "Win"
        console_user = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    
    } | ConvertTo-Json
    
    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
    
    $response    

}
##############  BEGIN MAIN ##########################
$scriptStartTime = Get-Date

Write-Output "Jank RMM Version 2024.8.28b`n"

if ($Option) {
    switch ($Option) {
        "Invoke-Check-Software" {
            Invoke-Check-Software 
        }
         "DoSomething" {
            DoSomething 
        }
        "DoSomethingElse" {
            DoSomethingElse 
        }
        default {
            Write-Output "Invalid option specified." 
        }
    }
    exit
}


$computerSerial = (Get-WmiObject Win32_BIOS).SerialNumber
Write-Output "Serial Number: $computerSerial`n"
Write-Output "Hostname: $env:COMPUTERNAME`n"

# Remove bitlocker for computers that should be returned.
$killComputerSerials = @('23232323', '32323232')
if ($killComputerSerials -contains $computerSerial) {
    Write-Output "ERROR: Removing Bitlocker key to secure data"
    # manage-bde -forcerecovery
    Write-Output "Stopping script"
    # shutdown /s /t 30 /f
    exit
}


Invoke-Check-Remove-Junk-Software

Invoke-Delete-Old-Logs
Invoke-Check-BitLocker-Enabled
Invoke-Check-Antivirus
 
 

# Update Windows time to use any time server.
& reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v Type /t REG_SZ /d "AllSync" /f
& reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" /v NtpServer /t REG_SZ /d "time.windows.com,0xB time.cloudflare.com,0xB" /f

# Disable Controlled folder access
& reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access"  /v EnableControlledFolderAccess  /d 0 /t REG_DWORD /f

# Disable wscript.exe
& reg.exe add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "Enabled" /d 0 /t REG_DWORD /f

#F# Disable MSHTA
& takeown /F "C:\windows\system32\mshta.exe"
& icacls "C:\windows\system32\mshta.exe" /deny "*S-1-1-0:(RX)"



& ipconfig.exe /all
Write-Output ""


#F# Disable UCPD (UserChoice Protection Driver) 
# Disable this so we can script file associations relation to programs
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\UCPD" -Name Start -Value 4 -PropertyType DWORD -Force
Disable-ScheduledTask -TaskName "\Microsoft\Windows\AppxDeploymentClient\UCPD velocity"


Write-Output "Public IP: $(Invoke-RestMethod -Uri "http://ipv4.icanhazip.com")`n"

Write-Output "Logged in users"
query user
Write-Output ""

$OSinfo = Get-CimInstance -ClassName Win32_OperatingSystem
Write-Output "OS Install Date $($OSinfo.InstallDate)"
Write-Output "Windows Version: $($OSinfo.Caption), build $($osinfo.BuildNumber)"




Write-Output "Sending computer info to API"
Send-ComputerInfoToAPI


$duration = $(Get-Date) - $scriptStartTime
$totalSeconds = [math]::Round($duration.TotalSeconds, 2)
Write-Output "Script execution time: $totalSeconds seconds`n"


