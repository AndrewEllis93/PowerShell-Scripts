####################################################
#
# Title: Disable-InactiveADAccounts
# Date Created : 2017-09-22
# Last Edit: 2017-12-29
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# Notes:
# WARNING: THIS SCRIPT WILL OVERWRITE EXTENSIONATTRIBUTE3 FOR INACTIVE USERS, MAKE SURE YOU ARE NOT USING IT FOR ANYTHING ELSE
# This script is SLOW because it gets the most accurate last logon possible by comparing results from all DCs. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5.
#
####################################################

#Function declarations
Function Start-Logging{
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
    param (
        [Parameter(Mandatory=$true)][String]$LogDirectory,
        [Parameter(Mandatory=$true)][String]$LogName,
        [Parameter(Mandatory=$true)][Int]$LogRetentionDays
        )

    #Sets screen buffer from 120 width to 500 width. This stops truncation in the log.
    $ErrorActionPreference = 'SilentlyContinue'
    $pshost = get-host
    $pswindow = $pshost.ui.rawui
 
    $newsize = $pswindow.buffersize
    $newsize.height = 3000
    $newsize.width = 500
    $pswindow.buffersize = $newsize
 
    $newsize = $pswindow.windowsize
    $newsize.height = 50
    $newsize.width = 500
    $pswindow.windowsize = $newsize
    $ErrorActionPreference = 'Continue'

    #Remove the trailing slash if present. 
    If ($LogDirectory -like "*\"){$LogDirectory = $LogDirectory.substring(0,($LogDirectory.Length-1))

    #Create log directory if it does not exist already
    If (!(Test-Path $LogDirectory)){mkdir $LogDirectory}

    #Starts logging.
    New-Item -ItemType directory -Path $LogDirectory -Force | Out-Null
    $Today = Get-Date -Format M-d-y
    Start-Transcript -Append -Path ($LogDirectory + "\" + $LogName + "." + $Today + ".log") | Out-Null

    #Shows proper date in log.
    Write-Output ("Start time: " + (Get-Date))

    #Purges log files older than X days
    $RetentionDate = (Get-Date).AddDays(-$LogRetentionDays)
    Get-ChildItem -Path $LogDirectory -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $RetentionDate -and $_.Name -like "*.log"} | Remove-Item -Force
} 
Function Disable-InactiveADAccounts {
    <#
    .SYNOPSIS
    This script disables AD accounts older than the threshold (in days) and stamps them in ExtensionAttribute3 with the disabled date. It also sends an email report.

    .DESCRIPTION
    Make sure you read through the comments (as with all of these scripts). It just finds the last logon for all AD accounts and disables any that have been inactive for X number of days (depending on what threshold you set). The difference with this script is that it gets the most accurate last logon available by comparing the results from all domain controllers. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5. This makes it much more accurate. It also supports an exclusion AD group that you can put things like service accounts in to prevent them from being disabled. It will also email a report to the specified email addresses.
    "-ReportOnly" will skip actually disabling the AD accounts and just send an email report of inactivity instead. 

    .EXAMPLE
    Disable-InactiveADAccounts -To @("email@domain.com","email2@domain.com") -From "noreply@domain.com" -SMTPServer "server.domain.local" -UTCSkew -5 -OutputDirectory "C:\ScriptLogs\Disable-InactiveADAccounts" -ExclusionGroup "ServiceAccounts" -DaysThreshold 30 -ReportOnly $True

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    #>

    Param(
        [Parameter(Mandatory=$true)][string]$From,
        [boolean]$ReportOnly = $False, #If set to true, email report will be sent without disabling or stamping any AD accounts.
        [Parameter(Mandatory=$true)][string]$SMTPServer,
        [Parameter(Mandatory=$true)][array]$To, #Array. You can add more than one entry.
        [Parameter(Mandatory=$true)][int]$UTCSkew, #Accounting for the time zone difference, since some results are given in UTC. Eastern time is UTC-5. 
        [int]$DaysThreshold = 30, #Threshold of days of inactivity before disabling the user. Defaults to 30 days.
        [Parameter(Mandatory=$true)][string]$OutputDirectory, #Where to export CSVs etc.
        [string]$Subject = "Account Cleanup Report",
        [int]$MaxTryCount = 20, #Amount of times to try for identical DC results before giving up. 30 second retry delay after each failure.
        [string]$ExclusionGroup #AD group containing accounts to exclude.
    )

    #Remove trailing slash if present.
    If ($OutputDirectory -like "*\"){$OutputDirectory = $OutputDirectory.substring(0,($OutputDirectory.Length-1))

    #Declare try count at 0.
    $TryCount= 0

    #Get all DCs, add array names to vars array
    $DCnames = @()
    $DCs = Get-ADGroupMember 'Domain Controllers'
    $DCs | ForEach-Object {$DCnames += $_.Name}

    #Check that results match from each DC by comparing all results in order. If there is a mismatch, wait 30 seconds and retry, up to the MaxTryCount (default 20)
    While (($ComparisonResults -contains $False -or !$ComparisonResults) -and $TryCount -lt $MaxTryCount){
    #Fetch AD users from each DC, add to named array
        $DCnames | ForEach-Object {
            Write-Output ("Fetching last logon times from " + $_ + "...")
            New-Variable -Name $_ -Value (Get-ADUser -Filter {Enabled -eq $True} -Server $_ -Properties DistinguishedName,LastLogon,LastLogonTimestamp,whenCreated,Description | Sort-Object SamAccountName) -Force
        } 

        $ComparisonResults = @()
        
        ForEach ($i in 0..(($DCnames.Count)-1)){
            If ($i -le (($DCnames.Count)-2)){
                Write-Output ("Comparing results from " + $DCnames[$i] + " and " + $DCnames[$i+1] + "...")
                $NotEqual = Compare-Object (Get-Variable -Name $DCnames[$i]).Value (Get-Variable -Name $DCnames[$i+1]).Value -Property SamAccountName

                If (!$NotEqual) {$ComparisonResults += $True}
                Else {$ComparisonResults += $False}
            }
        }
        If ($ComparisonResults -contains $False){
            Write-Warning "One or more DCs returned differing results. This is likely just replication delay. Retrying..."
            $TryCount++
            Start-Sleep 30
        }
    }
    If ($TryCount -lt $MaxTryCount){Write-Output "All DC results are identical!"}
    Else {Throw "Try limit exceeded. Aborting."}

    #Get current time for comparison later. 
    $StartTime = Get-Date

    #User count so we know how many times to loop.
    $UserCount = (Get-Variable -Name $DCnames[0]).Value.Count

    #Create results array of the same size
    $FullResults = @($null) * $UserCount

    #Loop through array indexes
    ForEach ($i in 0..($UserCount -1)){
        #Grab user object from each resultant array, make array of each user object
        $UserEntries = @(0) * $DCnames.Count
        ForEach ($o in 0..($DCnames.Count -1)) {
            $UserEntries[$o] = (Get-Variable -Name $DCnames[$o]).Value[$i]
        }
        If (($UserEntries.SamAccountName | Select-Object -Unique).Count -gt 1){Throw "A user mismatch at index $i has occurred. Aborting."}

        #Find most recent LastLogon, whenCreated, and LastLogonTimestamp.
        If ($UserEntries.LastLogon){
            [datetime]$LastLogon = [datetime]::FromFileTimeUtc(($UserEntries | Measure-Object -Property LastLogon -Maximum).Maximum)
            [datetime]$TrueLastLogon = $LastLogon
        }
        Else {[datetime]$LastLogon = 0; $TrueLastLogon = 0} 

        If ($UserEntries.whenCreated){
            [datetime]$whenCreated = $UserEntries[0].whenCreated
        }
        Else {[datetime]$whenCreated = 0}

        If ($UserEntries.LastLogonTimestamp){
            [datetime]$LastLogonTimestamp = [datetime]::FromFileTimeUtc(($UserEntries | Measure-Object -Property LastLogonTimestamp -Maximum).Maximum)
        }
        Else {[datetime]$LastLogonTimestamp = 0}

        #If LastLogonTimestamp is newer, use that instead of LastLogon.
        If ($LastLogonTimestamp -gt $LastLogon){$TrueLastLogon = $LastLogonTimestamp}

        #UTC conversion
        If ($TrueLastLogon -ne 0){$TrueLastLogon = $TrueLastLogon.AddHours($UTCSkew)}

        #If TrueLastLogon is older than 20 years (essentially null/zero), set to true zero
        If ((New-TimeSpan -Start $TrueLastLogon -End $StartTime).Days -gt 7300){[string]$TrueLastLogon = $null}

        #Calculate days of inactivity.
        If ($TrueLastLogon -ne $null -and $TrueLastLogon -ne ""){$DaysInactive = (New-TimeSpan -Start $TrueLastLogon -End $StartTime).Days}
        Else {$DaysInactive = (New-TimeSpan -Start $whenCreated -End $StartTime).Days}

        #Create object for output array
        $OutputObj = New-Object -TypeName PSObject
        $OutputObj | Add-Member -MemberType NoteProperty -Name SamAccountName -Value $UserEntries[0].SamAccountName
        $OutputObj | Add-Member -MemberType NoteProperty -Name Enabled -Value $UserEntries[0].Enabled
        $OutputObj | Add-Member -MemberType NoteProperty -Name LastLogon -Value $TrueLastLogon
        $OutputObj | Add-Member -MemberType NoteProperty -Name whenCreated -Value $whenCreated
        $OutputObj | Add-Member -MemberType NoteProperty -Name DaysInactive -Value $DaysInactive
        $OutputObj | Add-Member -MemberType NoteProperty -Name GivenName -Value $UserEntries[0].GivenName
        $OutputObj | Add-Member -MemberType NoteProperty -Name Surname -Value $UserEntries[0].SurName
        $OutputObj | Add-Member -MemberType NoteProperty -Name Name -Value $UserEntries[0].Name
        $OutputObj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $UserEntries[0].DistinguishedName
        $OutputObj | Add-Member -MemberType NoteProperty -Name Description -Value $UserEntries[0].Description

        #Append object to output array and output preogress to console.
        $FullResults[$i] = $OutputObj
        $PercentComplete = [math]::Round((($i/$UserCount) * 100),2)
        Write-Output ("User: " + $OutputObj.SamAccountName + " - Last logon: $TrueLastLogon ($DaysInactive day(s) inactivity) - $PercentComplete% complete.")
    }

    Write-Output "Getting exclusion group members..."
    $UserExclusions = (Get-ADGroupMember -Identity $ExclusionGroup -ErrorAction Stop).SamAccountName

    #Splits "other" and "real" users into two different arrays.
    Write-Output "Filtering users..."
    $RealUsersResults = @()
    $RealUsersResults = $FullResults | Where-Object {$UserExclusions -notcontains $_.SamAccountName}

    $OtherUsersResults = @()
    $FullResults = $FullResults | Where-Object {$_ -ne $null}

    #For some reason compare-object is not working properly without specifying all properties. Don't know why. 
    $OtherUsersResults = Compare-Object $RealUsersResults $FullResults `
    -Property SamAccountName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description | 
    Select-Object SamAccountName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description

    #Add to UsersDisabled array for CSV report. Also disable and stamp accounts if ReportOnly is set to false (default).
    If (!$ReportOnly){
        $UsersDisabled = @()
        $RealUsersResults | ForEach-Object {
            If ($_.DaysInactive -ge $DaysThreshold){
                Write-Output ("Disabling " + $_.SamAccountName + "...")
                Disable-ADAccount -Identity $_.SamAccountName
                $Date = "INACTIVE SINCE " + (Get-Date)
                Set-ADUser -Identity $_.SamAccountName -Replace @{ExtensionAttribute3=$Date} -WhatIf
                $UsersDisabled += $_
            }
        }
    }
    Else {
        $UsersDisabled = @()
        $RealUsersResults | ForEach-Object {
            If ($_.DaysInactive -ge $DaysThreshold){
                $UsersDisabled += $_
            }
        }
    }

    #Filtered users - add to UsersNotDisabled array for CSV report
    $OtherInactiveUsers = @()
    $OtherUsersResults | ForEach-Object {
        If ($_.DaysInactive -ge $DaysThreshold){
            $OtherInactiveUsers += $_
        }
    }

    #Reports exclusion group members.
    $ExcludedUsersReport = $FullResults | Where-Object {$UserExclusions -contains $_.SamAccountName} | Select-Object * -ExcludeProperty Enabled,LastLogon,whenCreated,DaysInactive

    #Export CSVs to output directory
    If (!(Test-Path $OutputDirectory)){mkdir $OutputDirectory}
    $UsersDisabledCSV = $OutputDirectory + "\InactiveUsers-Disabled.csv"
    $UsersNotDisabledCSV = $OutputDirectory + "\InactiveUsers-Excluded.csv"
    $ExcludedUsersReportCSV = $OutputDirectory + "\Auto-Disable Exclusions.csv"
    $UsersDisabled | Export-CSV $UsersDisabledCSV -NoTypeInformation -Force
    $OtherInactiveUsers | Export-CSV $UsersNotDisabledCSV -NoTypeInformation -Force
    $ExcludedUsersReport | Export-CSV $ExcludedUsersReportCSV -NoTypeInformation -Force

    <#
    # This is here if you want to use it in conjunction with my Move-Disabled script. Just uncomment and replace with your scheduled task path. 
    Write-Output "Starting Move-Disabled task..."
    Start-ScheduledTask -TaskName "\Move-Disabled"
    #>

    #Send email with CSVs as attachments
    Write-Output "Sending email..."
    Send-MailMessage -Attachments @($UsersDisabledCSV,$UsersNotDisabledCSV,$ExcludedUsersReportCSV) -From $From -SmtpServer $SMTPServer -To $To -Subject $Subject

}

Function Get-ADUserLastLogon ([string]$UserName){
    ###NOT USED IN SCRIPT, JUST FOR UTILITY WHEN TWEAKING###
    #Credit: https://www.reddit.com/r/PowerShell/comments/3u737j/getaduser_lastlogon/ (user deleted their account)
    #I made some tweaks.

    $dcs = Get-ADDomainController -Filter {Name -like "*"}
      $time = 0
      $dt = 0
        foreach($dc in $dcs) {
        Try
        {
            $user = Get-ADUser -Server $dc -identity $userName -properties LastLogon,LastLogonTimestamp
            if($user.LastLogonTimeStamp -gt $time)
            {
                $time = $user.LastLogonTimeStamp
            }
            if ($user.LastLogon -gt $time)
            {
                $time = $user.LastLogon
            }   
        }
        Catch {}
    }
    $dt = [DateTime]::FromFileTime($time)

    $OutputObj = New-Object -TypeName PSObject
    $OutputObj | Add-Member -MemberType NoteProperty -Name SamAccountName -Value $user.SamAccountName
    $OutputObj | Add-Member -MemberType NoteProperty -Name Enabled -Value $user.Enabled
    $OutputObj | Add-Member -MemberType NoteProperty -Name LastLogon -Value $dt
    $OutputObj | Add-Member -MemberType NoteProperty -Name GivenName -Value $user.GivenName
    $OutputObj | Add-Member -MemberType NoteProperty -Name Surname -Value $user.SurName
    $OutputObj | Add-Member -MemberType NoteProperty -Name Name -Value $user.Name
    $OutputObj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $user.DistinguishedNameName

    Return $OutputObj
}

#Start logging.
Start-Logging -logdirectory "C:\ScriptLogs\Disable-InactiveADAccounts" -logname "Disable-InactiveADAccounts" -LogRetentionDays 30

#Start function.
Disable-InactiveADAccounts -To @("email@domain.com","email2@domain.com") -From "noreply@domain.com" -SMTPServer "server.domain.local" -UTCSkew -5 -OutputDirectory "C:\ScriptLogs\Disable-InactiveADAccounts" -ExclusionGroup "ServiceAccounts"

#Stop logging.
Stop-Transcript