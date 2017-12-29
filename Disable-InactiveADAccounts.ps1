####################################################
#
# AD account cleanup script
# Date Created : 9/22/17
# Author : PowerMonkey500
#
####################################################
#
# WARNING: THIS SCRIPT WILL OVERWRITE EXTENSIONATTRIBUTE3 FOR INACTIVE USERS, MAKE SURE YOU ARE NOT USING IT FOR ANYTHING ELSE
# This script is SLOW because it gets the most accurate last logon possible by comparing results from all DCs. By default the lastlogontimestamp is only replicated every 14 days minus a random percentage of 5.
#
####################################################

#FUNCTION DECLARATIONS
#===================================================================================

#Logging function - starts transcript and cleans logs older than specified retention date.
Function Start-Logging{
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
    Get-ChildItem -Path $LogDirectory -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $RetentionDate } | Remove-Item -Force
} 

###NOT USED IN SCRIPT, JUST FOR UTILITY WHEN TWEAKING###
Function Get-ADUserLastLogon ([string]$UserName){
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

#-----------------------------------
#Main script
#-----------------------------------
#Declarations
$From = "noreply@email.com"
$SMTPServer = "server.domain.local"
$To = @('email1@email.com','email2@email.com') #Array. You can add more than one entry.
$Subject = "Account Cleanup Report"
$TryCount = 0 #Leave this at 0.
$LogDirectory = "C:\Disable-InactiveADAccountsLog" #No trailing slash
$LogName = "Disable-InactiveADAccountsLog"
$MaxTryCount = 20 #Amount of times to try for identical DC results before giving up. 30 second retry delay after each failure.
$UTCSkew = -5 #Accounting for the time zone difference, since some results are given in UTC. Eastern time is UTC-5. 
$ExclusionsGroup = "ServiceAccts" #AD group containing accounts to exclude.
$DaysThreshold = 30 #Threshold of days of inactivity before disabling the user.

#Start logging
Start-Logging -logdirectory $LogDirectory -logname $LogName -LogRetentionDays 30

#Get all DCs, add array names to vars array
$DCnames = @()
If (!$DCs){$DCs = Get-ADGroupMember 'Domain Controllers'}
$DCs | % {$DCnames += $_.Name}

#Check that results match from each DC
While (($ComparisonResults -contains $False -or !$ComparisonResults) -and $TryCount -lt $MaxTryCount){
#Fetch AD users from each DC, add to named array
    $DCnames | % {
        #Filters / Exclusions. 
        Write-Output ("Fetching last logon times from " + $_ + "...")
        New-Variable -Name $_ -Value (Get-ADUser -Filter {Enabled -eq $True} -Server $_ -Properties DistinguishedName,LastLogon,LastLogonTimestamp,whenCreated,Description | Sort SamAccountName) -Force
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
If (!$StartTime){$StartTime = Get-Date}

#User count so we know how many times to loop.
$UserCount = (Get-Variable -Name $DCnames[0]).Value.Count

#Create results array of the same size
$FullResults = @($null) * $UserCount

#Loop through array indexes
ForEach ($i in 0..($UserCount -1)){
    #Grab user object from each resultant array, make array of each user object
    $UserEntries = @(0) *$DCnames.Count
    ForEach ($o in 0..($DCnames.Count -1)) {
        $UserEntries[$o] = (Get-Variable -Name $DCnames[$o]).Value[$i]
    }
    If (($UserEntries.SamAccountName | Select -Unique).Count -gt 1){Throw "A user mismatch at index $i has occurred. Aborting."}

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

    #UTC to EST
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
$UserExclusions = (Get-ADGroupMember -Identity $ExclusionsGroup).SamAccountName

#Splits "other" and "real" users into two different arrays.
Write-Output "Filtering users..."
$RealUsersResults = @()
$RealUsersResults = $FullResults | Where {$UserExclusions -notcontains $_.SamAccountName}

$OtherUsersResults = @()
$FullResults = $FullResults | Where {$_ -ne $null}

#For some reason compare-object is not working properly without specifying all properties. Don't know why. 
$OtherUsersResults = Compare-Object $RealUsersResults $FullResults `
-Property SamAccountName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description | `
select SamAccountName,enabled,lastlogon,whencreated,DaysInactive,givenname,surname,name,distinguishedname,Description

#Disable accounts with inactivity past days threshold, add to UsersDisabled array for CSV report
$UsersDisabled = @()
$RealUsersResults | % {
    If ($_.DaysInactive -ge $DaysThreshold){
        Write-Output ("Disabling " + $_.SamAccountName + "...")
        Disable-ADAccount -Identity $_.SamAccountName
        $Date = "INACTIVE SINCE " + (Get-Date)
        Set-ADUser -Identity $_.SamAccountName -Replace @{ExtensionAttribute3=$Date} -WhatIf
        $UsersDisabled += $_
    }
}

#Filtered users - add to UsersNotDisabled array for CSV report
$OtherInactiveUsers = @()
$OtherUsersResults | % {
    If ($_.DaysInactive -ge $DaysThreshold){
        $OtherInactiveUsers += $_
    }
}

#Reports "Auto-Disable Exclusions-ENT" members
$ExcludedUsersReport = $FullResults | Where {$UserExclusions -contains $_.SamAccountName} | Select * -ExcludeProperty Enabled,LastLogon,whenCreated,DaysInactive

#Export CSVs to logging directory
$UsersDisabledCSV = $LogDirectory + "\InactiveUsers-Disabled.csv"
$UsersNotDisabledCSV = $LogDirectory + "\InactiveUsers-Excluded.csv"
$ExcludedUsersReportCSV = $LogDirectory + "\Auto-Disable Exclusions.csv"
$UsersDisabled | Export-CSV $UsersDisabledCSV -NoTypeInformation -Force
$OtherInactiveUsers | Export-CSV $UsersNotDisabledCSV -NoTypeInformation -Force
$ExcludedUsersReport | Export-CSV $ExcludedUsersReportCSV -NoTypeInformation -Force

<#
Write-Output "Starting Move-Disabled task..."
Start-ScheduledTask -TaskName "\Move-Disabled"
#>

#Send email with CSVs as attachments
Write-Output "Sending email..."
Send-MailMessage -Attachments @($UsersDisabledCSV,$UsersNotDisabledCSV,$ExcludedUsersReportCSV)`
 -From $From -SmtpServer $SMTPServer -To $To -Subject $Subject

Stop-Transcript
