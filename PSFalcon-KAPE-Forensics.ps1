#Requires -Version 5.1
#Requires -Modules @{ModuleName='PSFalcon';ModuleVersion='2.2.8'}
#Requires -RunAsAdministrator

<#
.SYNOPSIS
  This script will copy and execute the KAPE forensics tool on a remote 
  Microsoft Windows host using CrowdStrike API's and RTR

.DESCRIPTION
  Script that leverages the PSFalcon PowerShell module
  https://github.com/CrowdStrike/psfalcon
  Version 2.2.1 has been tested with this script

.REQUIREMENTS
  Requires API client & key and API scopes:Access level -  Hosts:Read, Real Time 
  Response (admin):Read/Write, Real Time 
  Response:Read/Write
  Support and Resources --> API Clients and Keys --> Add New API Client
  Requires KAPE-RTR.zip to be uploaded to the CrowdStrike Console
  Host Setup and Management --> Response and Containment --> Response Scripts and Files --> "PUT Files"
  

.INPUTS
  Users are prompted to select the appropriate CrowdStrike Cloud  
  Users must supply their clientID and secret API keys
  Users must supply either the host's AID or host name

.OUTPUTS
  Verbose logging to C:\Temp\PSFalcon-KAPE-Forensics.log
  
.NOTES
  Version:        1.1
  Script Name:    PSFalcon-KAPE-Forensics.ps1
  Author:         Gregory Fuentes - gregory.fuentes@luminator.com
  Creation Date:  2/27/205
  Purpose/Change: Initial script development
  

#>

# Import the psfalcon module - REQUIRES the PSFalcon PowerShell Module be placed in one of the PowerShell Modules directories
Import-Module -Name PSFalcon -Force -PassThru
Import-Module -Name Az -Force -PassThru

# Initialize some Variables
$LogFolder = "C:\Temp\PSFalcon"
$LogFile = $LogFolder + "\" + "PSFalcon-KAPE-Forensics.log"
    
# Create C:\Temp\PSFalcon directory
New-Item -Path $LogFolder -ItemType Directory -Force -ErrorAction SilentlyContinue

# Logging function
Function Write-Log
{
	param (
        [Parameter(Mandatory=$True)]
        [array]$LogOutput,
        [Parameter(Mandatory=$False)]
        [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
        [string]$level = "INFO",
        [Parameter(Mandatory=$True)]
        [string]$Path
	)

	#"[" + (Get-Date -f g) + "] " + $level + ": " + $logOutput | Out-File $Path -Append
    "[" + (Get-Date -UFormat "%m/%d/%y %T %p") + "] " + $level + ": " + $logOutput | Out-File $Path -Append


}

# Initialize the log file
$initLog = "`r`n[" + (Get-Date -UFormat "%m/%d/%y %T %p") + "] Starting script execution" | Out-File -FilePath $LogFile -Append

Function Select-HostqueryType{
#Clear-Host

    do {
    Write-Host "`n========================== SELECT HOST =============================="
    Write-Host "    PLEASE SELECT AN OPTION BELOW TO EXECUTE THE KAPE FORENSICS TOOL"
    Write-Host "`'1' TARGET HOST USING AID"
    Write-Host "`'2' TARGET HOST USING HOSTNAME"
    Write-Host "`'Q' QUIT"
    Write-Host "======================================================================="

    # Prompt user to select one of the CrowdStrike Cloud environments
    $choice = Read-Host "`nENTER CHOICE"

        } until (($choice -eq '1') -or ($choice -eq '2') -or ($choice -eq 'Q') )

            switch ($choice) {
                '1'{
                    Write-Host "`nYOU HAVE SELECTED TO USE THE AID OF THE HOST"
                    $hostquerymethod = "aid"
                    $hostquery = Read-Host "`nENTER THE AID"
                    
                    
            }
                '2'{
                    Write-Host "`nYOU HAVE SELECTED TO USE THE HOSTNAME OF THE HOST"
                    $hostquerymethod = "hostname"
                    $hostquery = Read-Host "`nENTER THE HOSTNAME"
            }

                'Q'{
                    Write-Host "`nEXITING THE MENU. PLEASE NOTE YOU MUST SELECT EITHER AID OR HOSTNAME TO PROCEED."
                    $hostquery = "quit"

            }
    }

    If($hostquery -ne "quit") {
        # Log the choice from above
        Write-Log -level INFO -LogOutput "User choose to find the host via $hostquerymethod." -Path $LogFile
        Return $hostquerymethod, $hostquery

    }

    If($hostquery -eq "quit") {
        # Log that the user choose to quit
        Write-Log -level INFO -LogOutput "User choose to quit the menu. Execution halting." -Path $LogFile
        Break
    }

}


Function CS-Cloud {
Clear-Host

    do {
    Write-Host "`n============= SELECT THE APPROPRIATE CROWDSTRIKE CLOUD ================"
    Write-Host "`'1' FOR US-1 CLOUD"
    Write-Host "`'2' FOR US-2 CLOUD"
    Write-Host "`'3' FOR EU CLOUD"
    Write-Host "`'4' FOR GOV CLOUD"
    Write-Host "`'Q' TO QUIT"
    Write-Host "======================================================================="

    # Prompt user to select one of the CrowdStrike Cloud environments
    $choice = Read-Host "`nENTER CHOICE"

        } until (($choice -eq '1') -or ($choice -eq '2') -or ($choice -eq '3') -or ($choice -eq '4') -or ($choice -eq 'Q') )

            switch ($choice) {
                '1'{
                    Write-Host "`nYou have selected the US-1 Cloud"
                    $cloud = "us-1"
            }
                '2'{
                    Write-Host "`nYou have selected the US-2 Cloud"
                    $cloud = "us-2"
            }
                '3'{
                    Write-Host "`nYou have selected the EU Cloud"
                    $cloud = "eu-1"
            }
                '4'{
                    Write-Host "`nYou have selected the GOV Cloud"
                    $cloud = "us-gov-1"
            }
                'Q'{
                    Write-Host "`nExiting menu. Please note you MUST select one of the CrowdStrike Cloud environments."
                    $cloud = "quit"
                    
            }
    }

    If($cloud -ne "quit") {
        # Log the choice from above
        Write-Log -level INFO -LogOutput "User choose the CrowdStrike $cloud Cloud." -Path $LogFile
        Return $cloud
    
    }

    If($cloud -eq "quit") {
        # Log that the user choose to quit
        Write-Log -level INFO -LogOutput "User choose to quit the menu. Execution halting." -Path $LogFile
        Break
    }

}
#endregion Functions

# Prompt the user for the CrowdStrike Cloud environment
$cloudenv = CS-Cloud

# Prompt for the API clientid and secret
$clientid = Read-Host -Prompt 'INPUT YOUR CLIENT ID API KEY'
$secret = Read-Host -Prompt 'INPUT YOUR API SECRET'

# Force TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Request an oAUTH2 token
try {

Request-FalconToken -ClientId $clientid -ClientSecret $secret -Cloud $cloudenv;
    If ((Test-FalconToken).Token -eq $true) {
        Write-Host "`n`rWE RECEIVED A TOKEN. PROCEEDING.`n`r"
            # Log that a token was received
            Write-Log -level INFO -LogOutput "Token received successfully." -Path $LogFile
    }

} catch {

        Write-Host "`n`rERROR! WE DID NOT RECEIVE A TOKEN!`n`r"
            # Log that a token was NOT received
            Write-Log -level ERROR -LogOutput "Token was NOT received successfully." -Path $LogFile
            Break
}

# Gather information from the Select-HostQueryType function
$Hostqmethod, $Hostq = Select-HostqueryType

# Determine the operating system, hostname and/or AID
If($Hostqmethod -ieq "aid") { $oscheck = Get-FalconHost -Ids $hostq | Select-Object os_version, hostname
    
    If($oscheck.os_version -inotmatch "windows") {

        Write-Host "`n`rERROR: THIS SCRIPT ONLY SUPPORTS MICROSOFT WINDOWS OPERATING SYSTEMS. QUITTING SCRIPT..`n`r"
        Write-Log -level ERROR -LogOutput "THIS SCRIPT ONLY SUPPORTS MICROSOFT WINDOWS OPERATING SYSTEMS. QUITTING SCRIPT" -Path $LogFile
        Revoke-FalconToken

        }else{

        Write-Host "`n`rMICROSOFT WINDOWS OPERATING SYSTEM DETECTED. PROCEEDING..`n`r"
        Write-Log -level INFO -LogOutput "MICROSOFT WINDOWS OPERATING SYSTEM DETECTED. PROCEEDING" -Path $LogFile
        # Define a variable to hold the AID
        $hostaid = $hostq
    }
}


# Determine the operating system, hostname and/or AID
If($hostqmethod -ieq "hostname") { $oscheck1 = Get-FalconHost -Filter "hostname:['$hostq']" -Detailed | Select-Object os_version, device_id

    If($oscheck.os_version -inotmatch "windows") {

        Write-Host "`n`rERROR: THIS SCRIPT ONLY SUPPORTS MICROSOFT WINDOWS OPERATING SYSTEMS. QUITTING SCRIPT..`n`r"
        Write-Log -level ERROR -LogOutput "THIS SCRIPT ONLY SUPPORTS MICROSOFT WINDOWS OPERATING SYSTEMS. QUITTING SCRIPT" -Path $LogFile
        Revoke-FalconToken
        Break

        }else{

        Write-Host "`n`rMICROSOFT WINDOWS OPERATING SYSTEM DETECTED. PROCEEDING..`n`r"
        Write-Log -level INFO -LogOutput "MICROSOFT WINDOWS OPERATING SYSTEM DETECTED. PROCEEDING" -Path $LogFile
        # Define a variable to hold the AID
        $hostaid = $oscheck1.device_id

    }
 }



# Initialize the connection to the remote machine
#--------------------------------------------------------------------
#--------------------------------------------------------------------
# IMPORTANT - Start-FalconSession Requires: 'real-time-response:read'
#--------------------------------------------------------------------
#--------------------------------------------------------------------
$Init = Start-FalconSession -HostId $hostaid

#regionFileCopyandFileExecution

# Copy KAPE-RTR.zip on the remote host
Try { 

    Write-Host "Putting KAPE-RTR.zip on host"
    Write-Log -level INFO -LogOutput "Putting KAPE-RTR.zip on host" -Path $LogFile
    $put1 = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command put -Arguments KAPE-RTR.zip
    

    $put1Complete = Confirm-FalconCommand -CloudRequestId $put1.cloud_request_id
    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error checking for file copy status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error checking for file copy status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }

$updSess1 = Update-FalconSession -hostid $($hostaid)


# Extract C:\KAPE-RTR.zip to C:\KAPE-RTR on the remote host
Try { 

    Write-Host "Extracting KAPE-RTR"
    Write-Log -level INFO -LogOutput "Extracting KAPE-RTR" -Path $LogFile
    $x = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command 'runscript' -Arguments '-Raw=```Expand-Archive -LiteralPath C:\KAPE-RTR.zip -DestinationPath C:\KAPE-RTR -Force``` -Timeout=900'


    $ExtractComplete = Confirm-FalconCommand -CloudRequestId $x.cloud_request_id
    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error checking for file extraction status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error checking for file extraction status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }

# Checking to see if file extraction has completed
While($ExtractComplete.count -eq 0){

    $updSess2 = Update-FalconSession -hostid $($hostaid)
    Write-Host "File extraction still running. Will check again in 10 seconds..."
    Write-Log -level INFO -LogOutput "File extraction still running. Will check again in 10 seconds..." -Path $LogFile
    Start-Sleep -Seconds 10

        $ExtractComplete = Confirm-FalconCommand -CloudRequestId $x.cloud_request_id
}

$ExtractStatus = Confirm-FalconCommand -CloudRequestId $x.cloud_request_id

    if($ExtractStatus.complete -eq "True") {
        Write-Host "File extraction completed successfully"
        Write-Log -level INFO -LogOutput "File extraction completed successfully" -Path $LogFile
    }


$updSess3 = Update-FalconSession -hostid $($hostaid)

Start-Sleep -seconds 300

# Execute KAPE
Try { 

    Write-Host "Executing KAPE"
    Write-Log -level INFO -LogOutput "Executing KAPE" -Path $LogFile
    Write-Host "Creating IR directory in C: drive...."
    #New-Item -ItemType Directory -Force -Path "C:\IR"

    $execKAPE = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command 'runscript' -Arguments '-Raw=```C:\KAPE-RTR\KAPE\kape.exe --tsource C: --target KapeTriage --tdest C:\IR --mdest C:\mdest --tflush --mflush --zip Triage --module CrowdStrike_CrowdResponse,Chainsaw,!EZParser,MFTECmd,RegRipper,AmcacheParser,EvtxECmd,PECmd,RecentFileCacheParser,WxTCmd,Windows_ARPCache,Windows_DNSCache``` -Timeout=900'
    $exec1Complete = Confirm-FalconCommand -CloudRequestId $execKAPE.cloud_request_id

    Start-Sleep -seconds 100

    }

Catch {

    Write-Host "Error checking for KAPE execution status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error checking for KAPE execution status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }



# Checking to see if KAPE execution has completed
Write-Host "Checking if the KAPE process is running on the remote host"
Write-Log -level INFO -LogOutput "Checking if the KAPE process is running on the remote host" -Path $LogFile
$KAPECompleteOutput = Invoke-FalconRTR -HostID $hostq -Command 'runscript' -Arguments '-Raw=```Get-Process -name "kape"```'

While($KAPECompleteOutput -imatch "System.Diagnostics.Process" -OR !(Get-ChildItem -Path "C:\IR" -Filter "*.zip")){


    #$updSess4 = Update-FalconSession -hostid $($hostaid)
    Write-Host "The KAPE process is still running on the remote host. Checking again in shortly..."
    Write-Log -level INFO -LogOutput "The KAPE process is still running on the remote host. Checking again shortly..." -Path $LogFile

    $KAPECompleteOutput = Invoke-FalconRTR -HostID $hostq -Command 'runscript' -Arguments '-Raw=```Get-Process -name "kape"```'
    Write-Host "Checking to see if Kape is done...."
 
}

# Sleep for 5 seconds
Start-Sleep -Seconds 100
$updSess5 = Update-FalconSession -hostid $($hostaid)


#Rename Output directory to Triage.zip
Try {
    Write-Host "Renaming Triage Directory"
    Write-Log -level INFO -LogOutput "Renaming Triage Directory" -Path $LogFile
    Get-ChildItem -Path "C:\IR" | where-object { $_.Name -like "*Triage.zip*" } | %{ rename-item -LiteralPath $_.FullName -NewName "Triage.zip" }
    Get-ChildItem -Path "C:\IR"
    }
Catch {
    Write-Host "Something is wrong with renaming Triage Directory"
}


# Zip up the results of the KAPE execution

Try { 

    Write-Host "Showing IR Directory"
    Get-ChildItem -Path "C:\IR"
    Write-Host "Zipping results of the KAPE execution"
    Write-Log -level INFO -LogOutput "Zipping results of the KAPE execution" -Path $LogFile
    Get-ChildItem -Path "C:\IR" | where-object { $_.Name -like "*Triage.zip*" } | %{ rename-item -LiteralPath $_.FullName -NewName "Triage.zip" }
    $DeviceName = (Get-FalconHost -Id $hostaid).Hostname
    $execz = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command zip -Arguments "C:\IR\*Triage.zip C:\Windows\Temp\Triage.zip"
    
    $exec2Complete = Confirm-FalconCommand -CloudRequestId $execz.cloud_request_id
    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error checking for zip execution status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error checking for zip execution status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }


# Sleep for 5 seconds
Start-Sleep -Seconds 5
$updSess6 = Update-FalconSession -hostid $($hostaid)

# Sleep for 5 seconds
Start-Sleep -Seconds 5

# Upload the zipped results of the KAPE execution to Azure Blob Storage Account
Try { 

    Write-Host "Uploading the zipped results of the KAPE execution to Azure Blob Storage Account"

    try {
        #Upload to Azure Blob using account key

        # Variables to upload to Azure Blob storage
        $storageAccountName = "ltgincidentresponse"
        $containerName = "csevidence"
        $localFilePath = "C:\IR\Triage.zip"
        $Hostname = (Get-FalconHost -Id $hostq).hostname
        $date = Get-Date -Format "yyyyMMdd"
        $blobName = "$Hostname-$date-Triage.zip"

        #Azure Storage Account Key stored in 'ASU' Environment Variable
        $key = $env:ASU

        #Context
        $cont = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $key

        # Generate SAS token
        $sasToken = New-AzStorageAccountSASToken -Service blob -ResourceType container,object -Permission racwdlup -ExpiryTime (get-date).AddDays(1) -Context $cont

        # Create context
        $context = New-AzStorageContext -StorageAccountName $storageAccountName -SasToken $sasToken

        # Upload file
        Set-AzStorageBlobContent -Container $containerName -File $localFilePath -Blob $blobName -Context $context  
        
        Write-Host "File '$Hostname-$date-Triage.zip' uploaded successfully to '$containerName'"
    } catch {
        Write-Error "Error uploading file: $($_.Exception.Message)"
    }

    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error checking for uploading zipped file status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error removing C:\$($DeviceName) from the remote host status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }


Write-Host "Removing Files and Folders used for Host IR/Foresnics..."

# Delete KAPE-RTR Folder from the remote host
Try { 

    Write-Host "Removing C:\KAPE-RTR.zip from the remote host"
    Write-Log -level INFO -LogOutput "Removing C:\KAPE-RTR.zip from the remote host" -Path $LogFile
    
    $cleanup1 = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command rm -Arguments '-Force C:\KAPE-RTR.zip'

    $cleanup1Complete = Confirm-FalconCommand -CloudRequestId $cleanup1.cloud_request_id
    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error removing C:\KAPE-RTR.zip from the remote host status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error removing C:\KAPE-RTR.zip from the remote host status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }


While($cleanup1Complete -eq 0){

    Write-Host "Checking if C:\KAPE-RTR.zip was deleted from the remote host again in 10 seconds..."
    Write-Log -level INFO -LogOutput "Checking if C:\KAPE-RTR.zip was deleted from the remote host again in 10 seconds..." -Path $LogFile
    Start-Sleep -Seconds 10

    $cleanup1Complete = Confirm-FalconCommand -CloudRequestId $cleanup1.cloud_request_id
}

$cleanup1Status = Confirm-FalconCommand -CloudRequestId $cleanup1.cloud_request_id


if($cleanup1Status.complete -eq "True") {
    Write-Host "Deletion of C:\KAPE-RTR.zip on the remote host completed successfully"
    Write-Log -level INFO -LogOutput "Deletion of C:\KAPE-RTR.zip on the remote host completed successfully" -Path $LogFile
}
    
    
# Sleep for 5 seconds
Start-Sleep -Seconds 5
$updSess7 = Update-FalconSession -hostid $($hostaid)

# Delete KAPE-RTR Folder from the remote host
Try { 

    Write-Host "Removing C:\KAPE-RTR from the remote host"
    Write-Log -level INFO -LogOutput "Removing C:\KAPE-RTR from the remote host" -Path $LogFile
    $cleanup2 = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command rm -Arguments '-Force C:\KAPE-RTR'

    $cleanup2Complete = Confirm-FalconCommand -CloudRequestId $cleanup2.cloud_request_id
    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error removing C:\KAPE-RTR from the remote host status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error removing C:\KAPE-RTR from the remote host status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }


While($cleanup2Complete -eq 0){

    $sessionUpdate10 = Update-FalconSession -hostid $($hostaid)
    Write-Host "Checking if C:\KAPE-RTR was deleted from the remote host again in 10 seconds..."
    Write-Log -level INFO -LogOutput "Checking if C:\KAPE-RTR was deleted from the remote host again in 10 seconds.." -Path $LogFile
    Start-Sleep -Seconds 10

        $cleanup2Complete = Confirm-FalconCommand -CloudRequestId $cleanup2.cloud_request_id
}

$cleanup2Status = Confirm-FalconCommand -CloudRequestId $cleanup2.cloud_request_id

if($cleanup2Status.complete -eq "True") {
    Write-Host "Deletion of C:\KAPE-RTR on the remote host completed successfully"
    Write-Log -level INFO -LogOutput "Deletion of C:\KAPE-RTR on the remote host completed successfully" -Path $LogFile
}


# Sleep for 5 seconds
Start-Sleep -Seconds 5
$updSess8 = Update-FalconSession -hostid $($hostaid)
    
# Delete IR Folder from the remote host
Try { 

    Write-Host "Removing directory C:\IR and its contents from the remote host"
    Write-Log -level INFO -LogOutput "Removing directory C:\IR and its contents from the remote host" -Path $LogFile
    $cleanup3 = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command rm -Arguments "-Force C:\IR"
    

    $cleanup3Complete = Confirm-FalconCommand -CloudRequestId $cleanup3.cloud_request_id
    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error removing C:\IR from the remote host status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error removing C:\IR from the remote host status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }
    
    
While($cleanup3Complete -eq 0){

    $sessionUpdate11 = Update-FalconSession -hostid $($hostaid)
    Write-Host "Checking if directory C:\IR and its contents were deleted from the remote host again in 10 seconds..."
    Write-Log -level INFO -LogOutput "Checking if directory C:\IR and its contents were deleted from the remote host again in 10 seconds.." -Path $LogFile
    Start-Sleep -Seconds 10

    $cleanup3Complete = Confirm-FalconCommand -CloudRequestId $cleanup3.cloud_request_id
}


$cleanup3Status = Confirm-FalconCommand -CloudRequestId $cleanup3.cloud_request_id

    if($cleanup3Status.complete -eq "True") {
        Write-Host "Deletion of directory C:\IR and its contents from the remote host completed successfully"
        Write-Log -level INFO -LogOutput "Deletion of directory C:\IR and its contents from the remote host completed successfully" -Path $LogFile
    }

$updSess9 = Update-FalconSession -hostid $($hostaid)

# Delete MDest Folder from the remote host
Try { 

    Write-Host "Removing directory C:\mdest and its contents from the remote host"
    Write-Log -level INFO -LogOutput "Removing directory C:\mdest and its contents from the remote host" -Path $LogFile
    $cleanup4 = Invoke-FalconAdminCommand -SessionId $Init.session_id -Command rm -Arguments "-Force C:\mdest"
    

    $cleanup4Complete = Confirm-FalconCommand -CloudRequestId $cleanup4.cloud_request_id
    Start-Sleep -seconds 10

    }

Catch {

    Write-Host "Error removing C:\mdest from the remote host status: $($error[0])"
    Write-Log -level ERROR -LogOutput "Error removing C:\mdest from the remote host status: $($error[0])" -Path $LogFile
    Revoke-FalconToken
    Return

    }
    
    
While($cleanup4Complete -eq 0){

    $sessionUpdate11 = Update-FalconSession -hostid $($hostaid)
    Write-Host "Checking if directory C:\mdest and its contents were deleted from the remote host again in 10 seconds..."
    Write-Log -level INFO -LogOutput "Checking if directory C:\mdest and its contents were deleted from the remote host again in 10 seconds.." -Path $LogFile
    Start-Sleep -Seconds 10

    $cleanup4Complete = Confirm-FalconCommand -CloudRequestId $cleanup4.cloud_request_id
}


$cleanup4Status = Confirm-FalconCommand -CloudRequestId $cleanup4.cloud_request_id

    if($cleanup4Status.complete -eq "True") {
        Write-Host "Deletion of directory C:\mdest and its contents from the remote host completed successfully"
        Write-Log -level INFO -LogOutput "Deletion of directory C:\mdest and its contents from the remote host completed successfully" -Path $LogFile
    }

$updSess9 = Update-FalconSession -hostid $($hostaid)


# Notify user to check for the file in the CrowdStrike Console
Write-Host "The file $Hostname-$date-Triage.zip is has been upload to the Azure Blob Storage Account."
Write-Log -level INFO -LogOutput "The file $Hostname-$date-Triage.zip is has been upload to the Azure Blob Storage Account...." -Path $LogFile

# Sleep for 5 seconds
Start-Sleep -Seconds 5

# Revoke Falcon Token
Write-Host "Script is complete. Revoking authorization token now."
Write-Log -level INFO -LogOutput "Script is complete. Revoking authorization token now." -Path $LogFile
# Finalize the log file
$FinalizeLog = "[" + (Get-Date -UFormat "%m/%d/%y %T %p") + "] Ending script execution`r`n" | Out-File -FilePath $LogFile -Append
Revoke-FalconToken
