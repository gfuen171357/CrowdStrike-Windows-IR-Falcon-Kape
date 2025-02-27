# Overview

The following script is meant to perform quick Incident Response on hosts Onboarded with CrowdStrike within
the Luminator Organization.

The purpose of this script is to using PSFalcon to run Remote commands on CrowdStrike Endpoints and run the tool "Kape"
for Incident Response and data collection zipping up the results. Afterwards, once KAPE is finished running the zipped results
folder is uploaded to a Luminator controller Azure Blob storage where the evidence is collected and the files/folders created
on the CrowdStrike Endpoint are deleted for quick response.

![CrowdStrike PS Falcon Kape Forensics](https://raw.githubusercontent.com/CrowdStrike/falconpy/main/docs/asset/cs-logo.png) 

![PowerShell Gallery](https://img.shields.io/powershellgallery/dt/psfalcon)
![PowerShell Gallery Version](https://img.shields.io/powershellgallery/v/psfalcon)

## Requirements

* An active Falcon subscription for the appropriate modules
* PowerShell 5.1+ (Windows), PowerShell 6+ (Linux/MacOS)
* A Falcon [OAuth2 API Client](https://falcon.crowdstrike.com/support/api-clients-and-keys) with appropriate roles
* Powershell Module 'PSFalcon' installed
* Powershell Module 'AZ' installed
* Azure storage account key stored in Environment Variable "ASU"

## Steps to use PSFalcon-Kape-Forensics.ps1

1. Open PowerShell in an Administrative Prompt
2. Download the PSFalcon-Kape-Forensics.ps1 to Local computer
3. Run the PSFalcon-Kape-Foresnics.ps1 in PowerShell

![ Start PSFalcon-Kape-Forensics](/StartKape.png)

![ PSFalcon Kape Forensics Usage](/PSFalcon-KapeUse.png)
4. After completion confirm in Azure Storage account that Evidence has been uploaded to Blob Storage.

![ Azure CrowdStrike IR Evidence](/Azure-KapeUse.png)


