####################################################
#
# Title: Disable-InactiveADComputers
# Date Created : 2017-09-22
# Last Edit: 2017-12-29
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# Notes:
# This finds the last logon for all AD computers and disables any that have been inactive for X number of days (depending on what threshold you set). 
# The difference with this script is that it gets the most accurate last logon available by comparing the results from all domain controllers. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5. This makes it much more accurate, but also it is a very slow. It also supports an exclusion AD group that you can put things like service computers in to prevent them from being disabled. It will also email a report to the specified email addresses.
# WARNING: THIS SCRIPT WILL OVERWRITE EXTENSIONATTRIBUTE3 FOR INACTIVE USERS, MAKE SURE YOU ARE NOT USING IT FOR ANYTHING ELSE
# This script is SLOW because it gets the most accurate last logon possible by comparing results from all DCs. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5.
#
####################################################

#Function declarations
Function Start-Logging {
    <#
    .SYNOPSIS
    This function starts a transcript in the specified directory and cleans up any files older than the specified number of days. 

    .DESCRIPTION
    Please ensure that the log directory specified is empty, as this function will clean that folder.

    .EXAMPLE
    Start-Logging -LogDirectory "C:\ScriptLogs\LogFolder" -LogName $LogName -LogRetentionDays 30

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    #>
    Param (
        [Parameter(Mandatory=$true)]
        [String]$LogDirectory,
        [Parameter(Mandatory=$true)]
        [String]$LogName,
        [Parameter(Mandatory=$true)]
        [Int]$LogRetentionDays
    )

   #Sets screen buffer from 120 width to 500 width. This stops truncation in the log.
   $ErrorActionPreference = 'SilentlyContinue'
   $pshost = Get-Host
   $pswindow = $pshost.UI.RawUI

   $newsize = $pswindow.BufferSize
   $newsize.Height = 3000
   $newsize.Width = 500
   $pswindow.BufferSize = $newsize

   $newsize = $pswindow.WindowSize
   $newsize.Height = 50
   $newsize.Width = 500
   $pswindow.WindowSize = $newsize
   $ErrorActionPreference = 'Continue'

   #Remove the trailing slash if present. 
   If ($LogDirectory -like "*\") {
       $LogDirectory = $LogDirectory.SubString(0,($LogDirectory.Length-1))
   }

   #Create log directory if it does not exist already
   If (!(Test-Path $LogDirectory)) {
       New-Item -ItemType Directory $LogDirectory -Force | Out-Null
   }

   $Today = Get-Date -Format M-d-y
   Start-Transcript -Append -Path ($LogDirectory + "\" + $LogName + "." + $Today + ".log") | Out-Null

   #Shows proper date in log.
   Write-Output ("Start time: " + (Get-Date))

   #Purges log files older than X days
   $RetentionDate = (Get-Date).AddDays(-$LogRetentionDays)
   Get-ChildItem -Path $LogDirectory -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $RetentionDate -and $_.Name -like "*.log"} | Remove-Item -Force
} 
Function Disable-InactiveADComputers {
    <#
    .SYNOPSIS
    This script disables AD computers older than the threshold (in days) and stamps them in ExtensionAttribute3 with the disabled date. It also sends an email report.

    .DESCRIPTION
    Make sure you read through the comments (as with all of these scripts). It just finds the last logon for all AD computers and disables any that have been inactive for X number of days (depending on what threshold you set). The difference with this script is that it gets the most accurate last logon available by comparing the results from all domain controllers. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5. This makes it much more accurate. It also supports an exclusion AD group that you can put things like service computers in to prevent them from being disabled. It will also email a report to the specified email addresses.
    "-ReportOnly" will skip actually disabling the AD computers and just send an email report of inactivity instead. 

    .EXAMPLE
    Disable-InactiveADComputers -To @("email@domain.com","email2@domain.com") -From "noreply@domain.com" -SMTPServer "server.domain.local" -UTCSkew -5 -OutputDirectory "C:\ScriptLogs\Disable-InactiveADComputers" -ExclusionGroup @('ServiceComputers','Auto-Disable Exclusions') -DaysThreshold 30 -ReportOnly $True

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    #>

    Param( 
        #From address for email reports.        
        [Parameter(Mandatory=$true)]
        [String]$From,

        #If $true, email report will be sent without disabling or stamping any AD computers.
        [switch]$ReportOnly = $False, 

        #SMTP server for sending reports.
        [Parameter(Mandatory=$true)]
        [String]$SMTPServer,

        #Array. You can add more than one entry.
        [Parameter(Mandatory=$true)]
        [Array]$To, 

        #Computering for the time zone difference, since some results are given in UTC. Eastern time is UTC-5. 
        [Parameter(Mandatory=$true)]
        [Int]$UTCSkew, 

        #Threshold of days of inactivity before disabling the computer. Defaults to 30 days.
        [Int]$DaysThreshold = 30, 

        #Where to export CSVs etc.
        [Parameter(Mandatory=$true)]
        [String]$OutputDirectory, 

        #Subject for email reports.
        [String]$Subject = "Computer Cleanup Report",

        #Amount of times to try for identical DC results before giving up. 30 second retry delay after each failure.
        [Int]$MaxTryCount = 20, 

        #AD group containing computers to exclude.
        [array]$ExclusionGroups 
    )

    #Remove trailing slash if present.
    If ($OutputDirectory -like "*\") {
        $OutputDirectory = $OutputDirectory.substring(0,($OutputDirectory.Length-1))
    }

    #Declare try count at 0.
    $TryCount= 0

    #Get all DCs, add array names to vars array
    $DCnames = (Get-ADGroupMember 'Domain Controllers').Name | Sort-Object

            #This just tests if we already have results for each DC, in case we are running this twice in the same session (mostly just for testing). 
            $ExistingResults = @(0) * $DCnames.Count
            $TestIteration = 0
            $DCnames | ForEach-Object {
                If (Get-Variable -Name $_ -ErrorAction SilentlyContinue){
                    $ExistingResults[$TestIteration] = $True
                }
                Else {
                    $ExistingResults[$TestIteration] = $False
                }
                $TestIteration++
            }

    #Check that results match from each DC by comparing all results in order. Retry if there is a mismatch, up to the MaxTryCount (default 20)
    While (($ComparisonResults -contains $False -or !$ComparisonResults) -and $TryCount -lt $MaxTryCount){
        #Makes sure we don't have any left over jobs from another run
        Get-Job | Stop-Job
        Get-Job | Remove-Job

        If ((!$ExistingResults -or $ExistingResults -contains $False) -or ($ComparisonResults -contains $False -or !$ComparisonResults)){
            #Fetch AD computers from each DC, add to named array
            Write-Output ""
            Write-Output "Starting data retrieval jobs..."

            ForEach ($DCName in $DCnames) {
                Start-Job -Name $DCName -ArgumentList $DCName -ScriptBlock {
                    param($DCName)
                    #Get AD results
                    Import-Module ActiveDirectory
                    $Results = Get-ADComputer -Filter {Enabled -eq $True} -Server $DCName -Properties DistinguishedName,LastLogon,LastLogonTimestamp,whenCreated,Description -ErrorAction Stop
                    $Results = $Results | Sort-Object -Property SamComputerName
                    Return $Results
                }
            } 

            #Wait for jobs to complete, show progress bar
            Wait-JobsWithProgress -Activity "Retrieving and sorting results from each DC. Please be patient"
            
            #Put results into named arrays for each DC
            ForEach ($DCName in $DCnames) {
                Set-Variable -Name $DCName -Value (Receive-Job -Name $DCName)
            }
        }

        $ComparisonResults = @()
        
        ForEach ($i in 0..(($DCnames.Count)-1)){
            If ($i -le (($DCnames.Count)-2)){
                Write-Output ("Comparing results from " + $DCnames[$i] + " and " + $DCnames[$i+1] + "...")
                $NotEqual = Compare-Object (Get-Variable -Name $DCnames[$i]).Value (Get-Variable -Name $DCnames[$i+1]).Value -Property SamComputerName

                If (!$NotEqual) {
                    $ComparisonResults += $True
                }
                Else {
                    $ComparisonResults += $False
                }
            }
        }
        If ($ComparisonResults -contains $False){
            Write-Warning "One or more DCs returned differing results. This is likely just replication delay. Retrying..."
            $TryCount++
        }
    }
    If ($TryCount -lt $MaxTryCount){
        Write-Output "All DC results are identical!"
    }
    Else {
        Throw "Try limit exceeded. Aborting."
    }

    #Removes the completes jobs.
    Get-Job | Remove-Job

    #Convert our results into hash tables because they are MUCH faster to process than PSObjects.
    If (!$ExistingResults -or $ExistingResults -contains $False){
        Write-Output ""
        Write-Output "Starting hash table conversions..."
        Write-Output ""
        ForEach ($DCName in $DCnames) {
            [array]$Data = (Get-Variable -Name $DCName).Value
            $Count = (Get-Variable -Name $DCName).Value.Count

            Start-Job -Name $DCName -ArgumentList $Data,$Count -ScriptBlock {
                param(
                    [array]$Data,
                    $Count
                )
                #Function to convert objects to hash tables
                #Credit: https://gist.github.com/dlwyatt/4166704557cf73bdd3ae
                Function ConvertTo-Hashtable{
                    [CmdletBinding()]
                    Param (
                        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
                        [psobject[]] $InputObject
                    )
                    Process{
                        ForEach ($object in $InputObject){
                            $hash = @{}
                            
                            ForEach ($property in $object.PSObject.Properties){
                                $hash[$property.Name] = $property.Value
                            }
                
                            $hash
                        }
                    }
                }
                #Declare the results array with empty hash tables to put the hash table objects into.
                [array]$HashResults = @(@{}) * $Count
                
                #Loop through each object, convert to hash table, add to HashResults array.
                $Iteration = 0
                $Data | ForEach-Object {
                    $HashResults[$Iteration] = $_ | ConvertTo-Hashtable
                    $Iteration++
                }
                Return $HashResults
            }
        } 
    }

    #Wait for jobs to complete, show progress bar
    Wait-JobsWithProgress -Activity "Converting results to hash tables"

    #Get the hash table results from the jobs.
    If (!$ExistingResults -or $ExistingResults -contains $False){
        ForEach ($DCName in $DCNames){
            Set-Variable -Name $DCName -Value (Receive-Job -Name $DCName) -Force
        }
    }
    
    #Get current time for comparison later. 
    $StartTime = Get-Date

    #Computer count so we know how many times to loop.
    $ComputerCount = (Get-Variable -Name $DCnames[0]).Value.Count

    #Create results array of the same size
    $FullResults = @($null) * $ComputerCount

    #Loop through array indexes
    ForEach ($i in 0..($ComputerCount -1)){
        #Grab computer object from each resultant array, make array of each computer object
        $ComputerEntries = @(@{}) * $DCnames.Count
        ForEach ($o in 0..($DCnames.Count -1)) {
            $ComputerEntries[$o] = (Get-Variable -Name $DCnames[$o]).Value[$i]
        }

        #If that computer's array contains a mismatch, bail. This should realistically never happen because we already compared the arrays.
        If (($ComputerEntries.SamComputerName | Select-Object -Unique).Count -gt 1){
            Throw "A computer mismatch at index $i has occurred. Aborting."
        }

        #Find most recent LastLogon, whenCreated, and LastLogonTimestamps, cast to datetimes.
        If ($ComputerEntries.LastLogon){
            [datetime]$LastLogon = [datetime]::FromFileTimeUtc(($ComputerEntries.LastLogon | Measure-Object -Maximum).Maximum)
            $LastLogon = $LastLogon.AddHours($UTCSkew)
            [datetime]$TrueLastLogon = $LastLogon
        }
        Else {[datetime]$LastLogon = 0; $TrueLastLogon = 0} 

        [datetime]$whenCreated = $ComputerEntries[0].whenCreated

        If ($ComputerEntries.LastLogonTimestamp){
            [datetime]$LastLogonTimestamp = [datetime]::FromFileTimeUtc(($ComputerEntries.LastLogonTimestamp | Measure-Object -Maximum).Maximum)
            $LastLogonTimestamp = $LastLogonTimestamp.AddHours($UTCSkew)
        }
        Else {[datetime]$LastLogonTimestamp = 0}

        #If LastLogonTimestamp is newer, use that instead of LastLogon. Realistically this should never happen, but just in case.
        If ($LastLogonTimestamp -gt $LastLogon){
            $TrueLastLogon = $LastLogonTimestamp
        }

        #If there is no last logon available from any attributes, or it is older than 20 years (essentially null/zero), use the date created instead.
        If ($TrueLastLogon -eq 0 -or !$TrueLastLogon -or (New-TimeSpan -Start $TrueLastLogon -End $StartTime).Days -gt 7300){
            [datetime]$TrueLastLogon = $whenCreated
        }

        #Calculate days of inactivity.
        $DaysInactive = (New-TimeSpan -Start $TrueLastLogon -End $StartTime).Days

        #Create object for output array
        $OutputObj = [PSCustomObject]@{
            SamComputerName=$ComputerEntries[0].SamComputerName
            Enabled=$ComputerEntries[0].Enabled
            LastLogon=$TrueLastLogon
            WhenCreated=$whenCreated
            DaysInactive=$DaysInactive
            GivenName=$ComputerEntries[0].GivenName
            Surname=$ComputerEntries[0].SurName
            Name=$ComputerEntries[0].Name
            DistinguishedName=$ComputerEntries[0].DistinguishedName
            Description=$ComputerEntries[0].Description
        }  

        #Append object to output array and output progress to console.
        $FullResults[$i] = $OutputObj
        $PercentComplete = [math]::Round((($i/$ComputerCount) * 100),2)
        Write-Output ("Computer: " + $OutputObj.SamComputerName + " - Last logon: $TrueLastLogon ($DaysInactive day(s) inactivity) - $PercentComplete% complete.")
    }

    #Gets exlusions, error action is set to stop
    If ($ExclusionGroups){
        $ComputerExclusions = @()
        ForEach ($ExclusionGroup in $ExclusionGroups){
            Write-Output "Getting `"$ExclusionGroup`" members..."
            $ComputerExclusions += (Get-ADGroupMember -Identity $ExclusionGroup -ErrorAction Stop).SamComputerName
        }
    }

    #Filter
    Write-Output "Filtering computers..."
    $FilteredComputersResults = $FullResults | Where-Object {$ComputerExclusions -notcontains $_.SamComputerName}
    $FullResults = $FullResults | Where-Object {$_ -ne $null}

    #For some reason compare-object is not working properly without specifying all properties. Don't know why. 
    $ExcludedComputersResults = Compare-Object $FilteredComputersResults $FullResults `
    -Property SamComputerName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description | 
    Select-Object SamComputerName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description

    #Add to ComputersDisabled array for CSV report. Also disable and stamp computers if ReportOnly is set to false (default).
    $InactiveComputersDisabled = @()
    If (!$ReportOnly){
        $FilteredComputersResults | ForEach-Object {
            If ($_.DaysInactive -ge $DaysThreshold){
                Write-Output ("Disabling " + $_.SamComputerName + "...")
                Disable-ADComputer -Identity $_.SamComputerName
                $Date = "INACTIVE SINCE " + (Get-Date)
                Set-ADComputer -Identity $_.SamComputerName -Replace @{ExtensionAttribute3=$Date}
                $InactiveComputersDisabled += $_
            }
        }
    }
    Else {
        $FilteredComputersResults | ForEach-Object {
            If ($_.DaysInactive -ge $DaysThreshold){
                Write-Output ("Disabling " + $_.SamComputerName + "...")
                Disable-ADComputer -Identity $_.SamComputerName -WhatIf
                $Date = "INACTIVE SINCE " + (Get-Date)
                Set-ADComputer -Identity $_.SamComputerName -Replace @{ExtensionAttribute3=$Date} -WhatIf
                $InactiveComputersDisabled += $_
            }
        }
    }

    #Filtered computers - add to ComputersNotDisabled array for CSV report
    $ExcludedInactiveComputers = @()
    $ExcludedComputersResults | ForEach-Object {
        If ($_.DaysInactive -ge $DaysThreshold){
            $ExcludedInactiveComputers += $_
        }
    }

    #Create output directory if it does not exist
    If (!(Test-Path $OutputDirectory)){
        New-Item -ItemType Directory $OutputDirectory
    }

    #Form the paths for the output files
    $InactiveComputersDisabledCSV = $OutputDirectory + "\InactiveComputers-Disabled.csv"
    $ComputersNotDisabledCSV = $OutputDirectory + "\InactiveComputers-Excluded.csv"

    #Export the CSVs
    $InactiveComputersDisabled | Export-CSV $InactiveComputersDisabledCSV -NoTypeInformation -Force
    $ExcludedInactiveComputers | Export-CSV $ComputersNotDisabledCSV -NoTypeInformation -Force

    #Send email with CSVs as attachments
    Write-Output "Sending email..."
    Send-MailMessage -Attachments @($InactiveComputersDisabledCSV,$ComputersNotDisabledCSV) -From $From -SmtpServer $SMTPServer -To $To -Subject $Subject

    <#
    # This is here if you want to use it in conjunction with my Move-Disabled script. Just uncomment and replace with your scheduled task path. 
    Write-Output "Starting Move-Disabled task..."
    Start-ScheduledTask -TaskName "\Move-Disabled"
    #>
}

Function Wait-JobsWithProgress {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Activity
    )
    # SHOW JOB PROGRESS
    $Total = (Get-Job).Count
    $CompletedJobs = (Get-Job -State Completed).Count

    # Loop while there are running jobs
    While ($CompletedJobs -ne $Total) {
        # Update progress based on how many jobs are done yet.
        # Write-Output "Waiting for background jobs: $CompletedJobs/$Total"
        Write-Progress -Activity $Activity -PercentComplete (($CompletedJobs/$Total)*100) -Status "$CompletedJobs/$Total jobs completed."

        # After updating the progress bar, get current job count
        $CompletedJobs = (Get-Job -State Completed).Count
    }
    Write-Progress -Activity $Activity -Completed
}

#Start logging.
Start-Logging -LogDirectory "C:\ScriptLogs\Disable-InactiveADComputers" -LogName "Disable-InactiveADComputers" -LogRetentionDays 30

#Start function.
. Disable-InactiveADComputers -To @("email@domain.com","email2@domain.com") -From "noreply@domain.com" -SMTPServer "server.domain.local" -UTCSkew -5 -DaysThreshold 60 -OutputDirectory "C:\ScriptLogs\Disable-InactiveADComputers" -ExclusionGroup @("ServiceAccts") -ReportOnly
#Stop logging.
Write-Output ("Stop time: " + (Get-Date))
Stop-Transcript