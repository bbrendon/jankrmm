
# Script lives in git

function SaveToFile {

    # Write-Output "in savetofile $lastMpStatusTS"
    # Save the variables to a text file
    $variables = @{
        LastMpStatusTS  = $lastMpStatusTS.ToString('s')
        # lastMpStatusTS  = $currentTS.ToString('s') 
        # LastEventPullTS = $varsFile.LastEventPullTS 
        LastEventPullTS = $currentTS.ToString('s') 
    }

    # Convert the variables to JSON format and save to a file
    $variables | ConvertTo-Json | Set-Content -Path $lastRunFile


}


function Test-IsDefenderInstalled {
    # Return $true if ONLY defender is installed and working.
    # Tested on Win11 and server 2022

    # Check the status of the Windows Defender Antivirus Service
    $defenderService = Get-Service -Name "WinDefend"

    # Write-Host "Windows Defender Antivirus service is running."
    if ($defenderService.Status -ne 'Running') {
        return $false
    }

    # Check if real-time protection is enabled
    $defenderStatus = Get-MpComputerStatus

    # Write-Host "Windows Defender real-time protection is enabled."
    if ($defenderStatus.RealTimeProtectionEnabled -eq $False) {
        return $false
    }

    return $true
}


$Config = Get-Content "C:\windows\rmm-config.json" | ConvertFrom-Json

$lastRunFile = "C:\windows\DefenderLastRunData.txt"

# Read the content of the text file and convert from JSON
$varsFile = Get-Content -Path $lastRunFile | ConvertFrom-Json

# Access the variables
# $varsFile.lastMpStatusTS
# $varsFile.LastEventPullTS 


# Eventlogs run in UTC so lets go! 
$currentTS = (Get-Date).ToUniversalTime()


# Convert $varsFile.lastMpStatusTS string to a DateTime object or initialize into the past if first run.
if ($varsFile.LastMpStatusTS) {
    $lastMpStatusTS = [DateTime]::Parse($varsFile.lastMpStatusTS)
} else {
    $lastMpStatusTS = $currentTS.AddDays(-7)
}

#################################################

# add stuff from get-mppreference to this?

# Calculate the time difference
$timeDifference = $currentTS - $lastMpStatusTS
 
$Healthy = $null

# Check if 30 minutes have passed
if ($timeDifference.TotalMinutes -ge 30) {
    # Run your command or script
    Write-Output "30 minutes have passed since the last update. Running the task..."

 
    $MpComputerStatusTrue = Get-MpComputerStatus | Select-Object -Property AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, IsTamperProtected, NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled

    # Check if all properties are set to True
    $allTrue = $MpComputerStatusTrue.PSObject.Properties.Value -eq $true -notcontains $false
    
    # Output any properties that are not set to True
    # $MpComputerStatusTrue.PSObject.Properties | Where-Object { $_.Value -ne $true } | ForEach-Object { 
    #     Write-Output "$($_.Name) is set to $($_.Value)" 
    # }
    
    
    # Output the overall result
    if ($allTrue) {
        Write-Output "All properties are set to True"
        $Healthy = $True
    } else {
        Write-Output "Not all properties are set to True"
        $Healthy = $False
    }
    
    $lastMpStatusTS = $currentTS



} else {
    Write-Output "Less than 30 minutes have passed since the last update."
}



##########################################################



$logName = 'Microsoft-Windows-Windows Defender/Operational'


if ($varsFile.LastEventPullTS ) {
    # $lastRunFormatted = $lastRun
    $lastRunFormatted = $varsFile.LastEventPullTS 
} else {
    $lastRunFormatted = $currentTS.AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ss")  # Default to a day before for first run
}

# Temp for testing. comment out later.
# $lastRunFormatted = $currentTS.AddDays(-7).ToString("yyyy-MM-ddTHH:mm:ss")

#$ExcludeIDs = '1000', '1001', '1002', '1013', '1150', '1151' , '2000', '2002', '2010', '5004', '5007'
# $ExcludeIDs = '1000', '1002', '1013', '1150', '1151', '2000', '2010', '2014', '5007'
$ExcludeIDs = '2123234', '328293'  # rubbish IDs to make things valid.



# Construct the FilterXPath query
$filterQuery = @"
<QueryList>
    <Query Id='0' Path='$logName'>
        <Select Path='$logName'>*[System[
            Provider[@Name='Microsoft-Windows-Windows Defender'] and 
            TimeCreated[@SystemTime&gt;='$lastRunFormatted'] and
            EventID!=$($ExcludeIDs -join ' and EventID!=')
        ]]</Select>
    </Query>
</QueryList>
"@

# Retrieve events using Get-WinEvent with FilterXPath
$events = Get-WinEvent -LogName $logName -FilterXPath $filterQuery -ErrorAction SilentlyContinue 
# remove line below. used for testing.
# $events = Get-WinEvent -LogName $logName -FilterXPath $filterQuery | Select-Object -First 1

# Output the events (for testing)
# $events
###################################################################
# API POST

# Check if any virus events were found or MpComputerStatus has something to report.
if ($events.Count -gt 0 -or $null -ne $Healthy) {
    # if ($events.Count -eq 1) {
    #     $eventsJson = "[ " + ($events | ConvertTo-Json) + " ]"
    # } else {
    #     $eventsJson = $events | ConvertTo-Json
    # }

    # If they system is saying Healthy, lets Double check :)
    if ($Healthy) {
        $Healthy = Test-IsDefenderInstalled
    }

    $serial = (Get-WmiObject -Class Win32_BIOS).SerialNumber  -replace ' ', '_'
    # $url = "https://x.x.com/api1/defender_events/$serial/"

    $url = $config.DefenderPushUrl -replace '\$serial', $serial

    $headers = @{
        "Content-Type" = "application/json"
    }

    # $status_data = @{}
    $status_data = @{ healthy = $Healthy }
    $body = ConvertTo-Json @{
        events = @($events)
        status = $status_data
    } 
    $body

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body
    Write-Output "respose: $response"

    if ($response.data.succeeded -eq 1) {
        # only update the lastrunfile if the response has success
        SaveToFile
        Write-Output "Data Push successful"
    } else {
        Write-Output "Data push failed"
    }
	

} else {
    Write-Output "No new data to post since last check at $lastRunFormatted UTC."
    # Update last run timestamp
    # $currentTS.ToString('s') | Out-File -FilePath $lastRunFile -Force
    SaveToFile
}

 