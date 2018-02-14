####################################################
#
# Title: Move-Disabled
# Date Created : 2017-12-28
# Last Edit: 2018-02-14
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# This moves disabled computers too. It rounds up disabled accounts and ages them through different OUs (0-30 days, 30-180 days, over 180 days).
#
# WARNING: THIS SCRIPT WILL OVERWRITE EXTENSIONATTRIBUTE3, MAKE SURE YOU ARE NOT USING IT FOR ANYTHING ELSE
#
# This script will not create the OUs for you.
# CREATE AN OU STRUCTURE UNDER YOUR PARENT OU AS FOLLOWS:
#
# Parent OU (specified by user)
# -> Users
# --> 0-30 Days
# --> 30-180 Days
# --> Over 180 Days
#
# -> Computers
# --> 0-30 Days
# --> 30-180 Days
# --> Over 180 Days
#
####################################################

Function Move-Disabled {
    <#
    .SYNOPSIS
    This moves disabled users and computers. It rounds up disabled accounts and ages them through different OUs (0-30 days, 30-180 days, over 180 days).

    .DESCRIPTION
    WARNING: THIS SCRIPT WILL OVERWRITE EXTENSIONATTRIBUTE3, MAKE SURE YOU ARE NOT USING IT FOR ANYTHING ELSE
    ExtensionAttribute3 is used to stamp the disablement date. This function will also clear ExtensionAttribute3 for any objects that are not disabled / not in the specified OU.
    "ReportOnly" will not take any actions, only output the WhatIfs to the console/log. RUN THIS FIRST to get an idea of what it will do.
    The InactivityDays argument is optional, but is there for if you are using my Disable-InactiveADAccounts script. This is so it can account for inactivity in its calculations. Please make sure you use the same on both.

    .EXAMPLE
    Move-Disabled -ParentOU "OU=Disabled Objects,DC=domain,DC=local" -InactivityDays 30 -ExclusionUserGroups @('ServiceAccts') -ExclusionOUs @('OU=Test,DC=domain,DC=local','OU=Test2,DC=domain,DC=local') -ReportOnly

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    Author : Andrew Ellis
    GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
    #>

    Param (
        [Parameter(Mandatory=$true)][string]$ParentOU,
        [array]$ExclusionUserGroups,
        [switch]$ReportOnly = $False,
        [int]$UserInactivityDays = 30,
        [int]$ComputerInactivityDays = 30,
        [array]$ExclusionOUs
    )

    #DECLARATIONS
        #Declares misc variables. 
        $MovedUsers = 0 #Leave at 0.
        $MovedComputers = 0 #Leave at 0.

    #MOVE NEWLY DISABLED USERS
        Write-Host ""
        Write-Output "NEWLY DISABLED MOVE:"
        #Gets all newly users. msExchRecipientTypeDetails makes sure we are excluding things like shared mailboxes.
        Write-Output "Getting newly disabled users..."
        $DisabledUsers = 
            Search-ADAccount -AccountDisabled -UsersOnly | 
                Get-ADUser -Properties msExchRecipientTypeDetails,info,Enabled,distinguishedName,ExtensionAttribute3 | 
                    Where-Object {
                        @(1,128,65536,2097152,2147483648,$null) -contains $_.msExchRecipientTypeDetails -and 
                        $_.DistinguishedName -notlike "*Builtin*" -and 
                        $_.DistinguishedName -notlike "*$ParentOU" -and 
                        $Exclusions.SamAccountName -notcontains $_.SamAccountName
        }

        #AD group filters if specified.
        If ($ExclusionUserGroups){
            [array]$FilterUserSAMs = @()
            ForEach ($ExclusionUserGroup in $ExclusionUserGroups){
                Write-Output "Getting $ExclusionUserGroup members..."
                $FilterUserSAMs += (Get-ADGroupMember $ExclusionUserGroup -ErrorAction Stop).SamAccountName
            }
            $DisabledUsers = $DisabledUsers | Where-Object {$FilterUserSAMs -notcontains $_.SamAccountName}
        }

        #OU filters if specified.
        If ($ExclusionOUs){
            [array]$FilterArray = @()
            ForEach ($ExclusionOU in $ExclusionOUs){
                $FilterArray += "`$_.DistinguishedName -NotLike `"*$ExclusionOU`""
            }
            $Filter = [scriptblock]::Create($FilterArray -join " -and ")
            $DisabledUsers = $DisabledUsers | Where-Object -FilterScript $Filter
        }

        Write-Output ($DisabledUsers.Count.toString() + " newly disabled user objects were found.")

        #Loops through the newly disabled users found.
        ForEach ($DisabledUser in $DisabledUsers){
            #Moves the user.
            Write-Output ("Moving user: " + $DisabledUser.SamAccountName + "...")
            If ($ReportOnly) {
                Move-ADObject -Identity $DisabledUser.DistinguishedName -TargetPath "OU=0-30 Days,OU=Users,$ParentOU" -WhatIf
            }
            Else {
                Move-ADObject -Identity $DisabledUser.DistinguishedName -TargetPath "OU=0-30 Days,OU=Users,$ParentOU"
            }
            $MovedUsers++

            #Sets the info (notes) field with the old OU.
            #Formats the new info field (notes). Retains old info if any exists.
            Write-Output ("Setting info field for user: " + $DisabledUser.SamAccountName + "...")
            #Gets the parent OU.
            $OU = $DisabledUser.DistinguishedName.Split(',',2)[1]
            If ([string]::IsNullOrWhiteSpace($DisabledUser.Info)){
                $NewInfo = "OLD OU: " + $OU
            }
            Else {
                $NewInfo = "OLD OU: " + $OU + "`n" + $DisabledUser.Info
            }
            If ($ReportOnly){
                Set-ADUser -Identity $DisabledUser.SamAccountName -Replace @{info=$NewInfo} -WhatIf
            }
            Else {
                Set-ADUser -Identity $DisabledUser.SamAccountName -Replace @{info=$NewInfo}
            }

            #Sets ExtensionAttribute3 for the date of disablement.
            If ($DisabledUser.ExtensionAttribute3 -notlike "INACTIVE*"){
                $Date = "DISABLED ON " + (Get-Date)
                Write-Output ("Setting ExtensionAttribute3 for user: " + $DisabledUser.SamAccountName + "...")
                If ($ReportOnly) {
                    Set-ADUser -Identity $DisabledUser.SamAccountName -Replace @{ExtensionAttribute3=$Date} -WhatIf
                }
                Else {
                    Set-ADUser -Identity $DisabledUser.SamAccountName -Replace @{ExtensionAttribute3=$Date}
                }
            }
        }

    #MOVE NEWLY DISABLED COMPUTERS
        #Get disabled computer accounts.
        Write-Output "Getting disabled computers..."
        $DisabledComputers =  Get-ADComputer -Filter * -Properties Enabled,Description,distinguishedName,ExtensionAttribute3 | Where-Object {
            $_.Enabled -eq $False -and 
            $_.DistinguishedName -notlike "*$ParentOU"
        }

        Write-Output ($DisabledComputers.Count.toString() + " newly disabled computer objects were found.")

        ForEach ($DisabledComputer in $DisabledComputers){
        #Moves the Computer.
            Write-Output ("Moving computer: " + $DisabledComputer.SamAccountName + "...")
            If ($ReportOnly) {
                Move-ADObject -Identity $DisabledComputer.DistinguishedName -TargetPath "OU=0-30 Days,OU=Computers,$ParentOU" -WhatIf
            }
            Else {
                Move-ADObject -Identity $DisabledComputer.DistinguishedName -TargetPath "OU=0-30 Days,OU=Computers,$ParentOU"
            }
            $MovedComputers++

            #Sets the description (notes) field with the old OU.
            #Formats the new description field (notes). Retains old Description if any exists.
            Write-Output ("Setting Description field for computer: " + $DisabledComputer.SamAccountName + "...")
            #Gets the parent OU.
            $OU = $DisabledComputer.DistinguishedName.Split(',',2)[1]
            If ([string]::IsNullOrWhiteSpace($DisabledComputer.Description)){
                $NewDescription = "OLD OU: " + $OU
            }
            Else{
                $NewDescription = "OLD OU: " + $OU + " | " + $DisabledComputer.Description
            }
            If ($ReportOnly){
                Set-ADComputer -Identity $DisabledComputer.SamAccountName -Replace @{Description=$NewDescription} -WhatIf
            }
            Else {
                Set-ADComputer -Identity $DisabledComputer.SamAccountName -Replace @{Description=$NewDescription}
            }

            #Sets ExtensionAttribute3 for the date of disablement.
            If ($DisabledComputer.ExtensionAttribute3 -notlike "INACTIVE*"){
                $Date = "DISABLED ON " + (Get-Date)
                Write-Output ("Setting ExtensionAttribute3 for computer: " + $DisabledComputer.SamAccountName + "...")
                If ($ReportOnly) {
                    Set-ADComputer -Identity $DisabledComputer.SamAccountName -Replace @{ExtensionAttribute3=$Date} -WhatIf
                }
                Else {
                    Set-ADComputer -Identity $DisabledComputer.SamAccountName -Replace @{ExtensionAttribute3=$Date}
                }
            }
        }

    #INCREMENT THROUGH OUS BASED ON AGE
        Write-Host ""
        Write-Output "OU INCREMENTATION:"
        #Gets objects in the disabled OU
        $DisabledOUUsers = Get-ADUser -Filter * -SearchBase $ParentOU -Properties ExtensionAttribute3,DistinguishedName,SamAccountName,Enabled | Where-Object {!$_.Enabled}
        $DisabledOUComputers = Get-ADComputer -Filter * -SearchBase $ParentOU -Properties ExtensionAttribute3,DistinguishedName,SamAccountName,Enabled | Where-Object {!$_.Enabled}

        #USERS
            #Declares counts for output.
            $30to180DayMovedUsers = 0
            $180DayMovedUsers = 0

            #Loops through users and checks if older than 30 days.
            ForEach ($DisabledOUUser in $DisabledOUUsers){
                #Sets the date disabled if not already set
                If ([string]::IsNullOrWhiteSpace($DisabledOUUser.ExtensionAttribute3) -or $DisabledOUUser.ExtensionAttribute3 -like "RE-ENABLED*"){
                    Write-Output ("Setting ExtensionAttribute 3 for user: " + $DisabledOUUser.SamAccountName + " (user was in disabled objects OU but did not have a disabled date.)")

                    $Date = "DISABLED ON " + (Get-Date)
                    If ($ReportOnly){
                        Set-ADUser -Identity $DisabledOUUser.SamAccountName -Replace @{ExtensionAttribute3=$Date} -WhatIf
                    }
                    Else {
                        Set-ADUser -Identity $DisabledOUUser.SamAccountName -Replace @{ExtensionAttribute3=$Date}
                    }

                    #Sets the variable for comparison in the rest of the loop. It was null. 
                    $DisabledOUUser.ExtensionAttribute3 = $Date
                }

                #Extracts the date disabled for comparison. 
                #If disabled by hand, count from the disable date
                If ($DisabledOUUser.ExtensionAttribute3 -like "DISABLED ON*"){
                    $DateDisabled = [datetime]($DisabledOUUser.ExtensionAttribute3.Replace('DISABLED ON ',''))
                    $DaysDisabled = (New-TimeSpan -Start $DateDisabled -End (Get-Date)).Days
                }
                #If auto-disabled because of inactivity (Disable-InactiveADAccounts script), add extra days to account for that.
                ElseIf ($DisabledOUUser.ExtensionAttribute3 -like "INACTIVE SINCE*"){
                    $DateDisabled = [datetime]($DisabledOUUser.ExtensionAttribute3.Replace('INACTIVE SINCE ',''))
                    $DaysDisabled = (New-TimeSpan -Start $DateDisabled.AddDays(($UserInactivityDays * -1)) -End (Get-Date)).Days
                }
                Else {Write-Error ($DisabledOUUser.SamAccountName + " has an invalid disable date in ExtensionAttribute3.")}

                #Increment through OUs
                If ($DaysDisabled -ge 30 -and $DaysDisabled -le 180 -and $DisabledOUUser.DistinguishedName -notlike "*OU=30-180 Days,OU=Users,$ParentOU"){
                    Write-Output ("Moving user to the 30-180 Days OU: " + $DisabledOUUser.SamAccountName)
                    If ($ReportOnly) {
                        Move-ADObject -Identity $DisabledOUUser.DistinguishedName -TargetPath "OU=30-180 Days,OU=Users,$ParentOU" -WhatIf
                    }
                    Else {
                        Move-ADObject -Identity $DisabledOUUser.DistinguishedName -TargetPath "OU=30-180 Days,OU=Users,$ParentOU"
                    }
                    $30to180DayMovedUsers++
                }
                Else {
                    If ($DaysDisabled -gt 180 -and $DisabledOUUser.DistinguishedName -notlike "*OU=Over 180 Days,OU=Users,$ParentOU"){
                        Write-Output ("Moving user to the Over 180 Days OU: " + $DisabledOUUser.SamAccountName)
                        If ($ReportOnly) {
                            Move-ADObject -Identity $DisabledOUUser.DistinguishedName -TargetPath "OU=Over 180 Days,OU=Users,$ParentOU" -WhatIf
                        }
                        Else {
                            Move-ADObject -Identity $DisabledOUUser.DistinguishedName -TargetPath "OU=Over 180 Days,OU=Users,$ParentOU"
                        }
                        $180DayMovedUsers++
                    }
                }
            }

        #COMPUTERS
            #Declares counts for output.
            $30to180DayMovedComputers = 0
            $180DayMovedComputers = 0


            #Loops through computers and checks if older than 90 days.
            ForEach ($DisabledOUComputer in $DisabledOUComputers){
                #Sets the date disabled if not already set
                If ([string]::IsNullOrWhiteSpace($DisabledOUComputer.ExtensionAttribute3) -or $DisabledOUComputer.ExtensionAttribute3 -like "RE-ENABLED*"){
                    Write-Output ("Setting ExtensionAttribute 3 for Computer: " + $DisabledOUComputer.SamAccountName + " (computer was in disabled objects OU but did not have a disabled date.)")

                    $Date = "DISABLED ON " + (Get-Date)
                    If ($ReportOnly){
                        Set-ADComputer -Identity $DisabledOUComputer.SamAccountName -Replace @{ExtensionAttribute3=$Date} -WhatIf
                    }
                    Else {
                        Set-ADComputer -Identity $DisabledOUComputer.SamAccountName -Replace @{ExtensionAttribute3=$Date}
                    }

                    #Sets the variable for comparison in the rest of the loop. It was null. 
                    $DisabledOUComputer.ExtensionAttribute3 = $Date
                }

                #Extracts the date disabled for comparison.
                #If disabled by hand, count from the disable date
                If ($DisabledOUComputer.ExtensionAttribute3 -like "DISABLED ON*"){
                    $DateDisabled = [datetime]($DisabledOUComputer.ExtensionAttribute3.Replace('DISABLED ON ',''))
                    $DaysDisabled = (New-TimeSpan -Start $DateDisabled -End (Get-Date)).Days
                }
                #If auto-disabled because of inactivity (Disable-InactiveADAccounts script), add extra days to account for that.
                ElseIf ($DisabledOUComputer.ExtensionAttribute3 -like "INACTIVE SINCE*"){
                    $DateDisabled = [datetime]($DisabledOUComputer.ExtensionAttribute3.Replace('INACTIVE SINCE ',''))
                    $DaysDisabled = (New-TimeSpan -Start $DateDisabled.AddDays(($ComputerInactivityDays * -1)) -End (Get-Date)).Days
                }
                Else {Write-Error ($DisabledOUComputer.SamAccountName + " has an invalid disable date in ExtensionAttribute3.")}

                #Increment through OUs
                If ($DaysDisabled -ge 30 -and $DaysDisabled -le 180 -and $DisabledOUComputer.DistinguishedName -notlike "*OU=30-180 Days,OU=Computers,$ParentOU"){
                    Write-Output ("Moving computer to the 30-180 Days OU: " + $DisabledOUComputer.SamAccountName)
                    If ($ReportOnly) {
                        Move-ADObject -Identity $DisabledOUComputer.DistinguishedName -TargetPath "OU=30-180 Days,OU=Computers,$ParentOU" -WhatIf
                    }
                    Else {
                        Move-ADObject -Identity $DisabledOUComputer.DistinguishedName -TargetPath "OU=30-180 Days,OU=Computers,$ParentOU"
                    }
                    $30to180DayMovedComputers++
                }
                Else{
                    If ($DaysDisabled -gt 180 -and $DisabledOUComputer.DistinguishedName -notlike "*OU=Over 180 Days,OU=Computers,$ParentOU"){
                        Write-Output ("Moving computer to the Over 180 Days OU: " + $DisabledOUComputer.SamAccountName)
                        If ($ReportOnly) {
                            Move-ADObject -Identity $DisabledOUComputer.DistinguishedName -TargetPath "OU=Over 180 Days,OU=Computers,$ParentOU" -WhatIf
                        }
                        Else {
                            Move-ADObject -Identity $DisabledOUComputer.DistinguishedName -TargetPath "OU=Over 180 Days,OU=Computers,$ParentOU"
                        }
                        $180DayMovedComputers++
                }
            }
        }

    #SUMMARY OUTPUT
        #Writes the counts of what was modified etc.
        Write-Output 'TOTALS:'
        $MovedUsers = $MovedUsers.tostring()
        Write-Output ($MovedUsers + ' user(s) moved to the "0-30 Days" OU.')
        $MovedComputers = $MovedComputers.tostring()
        Write-Output ($MovedComputers + ' computer(s) moved to the "0-30 Days" OU.')
        Write-Output ''
        $30to180DayMovedUsers = $30to180DayMovedUsers.tostring()
        Write-Output ($30to180DayMovedUsers + ' user(s) moved to the "30-180 Days" OU.')
        $30to180DayMovedComputers = $30to180DayMovedComputers.tostring()
        Write-Output ($30to180DayMovedComputers + ' computer(s) moved to the "30-180 Days" OU.')
        Write-Output ''
        $180DayMovedUsers = $180DayMovedUsers.tostring()
        Write-Output ($180DayMovedUsers + ' user(s) moved to the "Over 180 Days" OU.')
        $180DayMovedComputers = $180DayMovedComputers.tostring()
        Write-Output ($180DayMovedComputers + ' computer(s) moved to the "Over 180 Days" OU.')
        Write-Output ''

        #ATTRIBUTE CLEANUP
            #Gets all AD objects with ExtensionAttribute3 incorrectly set, and clears it."
            Write-Output ""
            Write-Output "ATTRIBUTE CLEANUP:"
            Write-Output "Finding enabled users with incorrect ExtensionAttribute3 attributes..."

            $MalformedUsers = Get-ADUser -Filter * -Properties DistinguishedName,ExtensionAttribute3,SamAccountName,Enabled | Where-Object {
                $_.DistinguishedName -NotLike "*$ParentOU" -and
                $_.Enabled -eq $True -and
                ![string]::IsNullOrEmpty($_.ExtensionAttribute3) -and 
                $_.ExtensionAttribute3 -notlike "DISABLED ON*" -and
                $_.ExtensionAttribute3 -notlike "INACTIVE SINCE*" -and
                $_.ExtensionAttribute3 -notlike "RE-ENABLED ON*"
            }
            $MalformedComputers = Get-ADComputer -Filter * -Properties DistinguishedName,ExtensionAttribute3,SamAccountName,Enabled | Where-Object {
                $_.DistinguishedName -NotLike "*$ParentOU" -and
                $_.Enabled -eq $True -and
                ![string]::IsNullOrEmpty($_.ExtensionAttribute3) -and 
                $_.ExtensionAttribute3 -notlike "DISABLED ON*" -and
                $_.ExtensionAttribute3 -notlike "INACTIVE SINCE*" -and
                $_.ExtensionAttribute3 -notlike "RE-ENABLED ON*"
            }

            Write-Output (($MalformedUsers.SamAccountName.Count).ToString() + " users were found.")
            Write-Output (($MalformedComputers.SamAccountName.Count).ToString() + " computers were found.")

            ForEach ($MalformedUser in $MalformedUsers){
                Write-Output ("Clearing ExtensionAttribute3 for " + $MalformedUser.SamAccountName + "...")
                If ($ReportOnly){
                    Set-ADUser -Identity $MalformedUser.SamAccountName -Clear ExtensionAttribute3 -WhatIf
                }
                Else {
                    Set-ADUser -Identity $MalformedUser.SamAccountName -Clear ExtensionAttribute3
                }
            }

            ForEach ($MalformedComputer in $MalformedComputers){
                Write-Output ("Clearing ExtensionAttribute3 for " + $MalformedComputer.SamAccountName + "...")
                If ($ReportOnly){
                    Set-ADComputer -Identity $MalformedComputer.SamAccountName -Clear ExtensionAttribute3 -WhatIf
                }
                Else {
                    Set-ADComputer -Identity $MalformedComputer.SamAccountName -Clear ExtensionAttribute3
                }
            }
}

#LOGGING FUNCTION - starts transcript and cleans logs older than specified retention date.
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

#Start logging
Start-Logging -LogDirectory "C:\ScriptLogs\Move-DisabledLog" -LogName "Move-DisabledLog" -LogRetentionDays 30

#Call function
Move-Disabled -ParentOU "OU=Disabled Objects,DC=domain,DC=local" -UserInactivityDays 30 -ComputerInactivityDays 60 -ReportOnly -ExclusionOUs @('OU=Test,DC=domain,DC=local','OU=Test2,DC=domain,DC=local') -ExclusionUserGroups @('ServiceAccts')

#Stop logging.
Write-Output ("Stop time: " + (Get-Date))
Stop-Transcript