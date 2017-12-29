####################################################
#
# Title: Send-PasswordNotices
# Date Created : 2017-05-01
# Last Edit: 2017-12-29
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# This sends password expiration notice emails to users at 1,2,3,7, and 14 days. Supports an AD exclusion group.
# Comment out this line starting with "Send-MailMessage" to just get output without actuall sending any email.
#
####################################################

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

    #Starts logging.
    New-Item -ItemType directory -Path $LogDirectory -Force | Out-Null
    $Today = Get-Date -Format M-d-y
    Start-Transcript -Append -Path ($LogDirectory + "\" + $LogName + "." + $Today + ".log") | Out-Null

    #Shows proper date in log.
    Get-Date

    #Purges log files older than X days
    $RetentionDate = (Get-Date).AddDays(-$LogRetentionDays)
    Get-ChildItem -Path $LogDirectory -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $RetentionDate  -and $_.Name -like "*.log"} | Remove-Item -Force
} 


Function Send-Notice
{
    <#
    .SYNOPSIS
    Customizes and sends an email message and subject based on the number of days left before password expiry.

    .DESCRIPTION
    Send-notice - sends emails to users based on days before password expiration.  Requires user email address, days before password expiration, password expiration date, and user account name variables.
    Notices are only sent if days before password is due to expire are equal to 1,2,3,7, or 14.
    
    .NOTES
    Title: Send-Notice
    Date Created : 2017-05-01   
    Last Edit: 2017-12-29
    Author : Andrew Ellis
    GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
    #>

    param(
        [Parameter(Mandatory=$True)][string]$usermail,
        [Parameter(Mandatory=$True)][Int]$days,
        [Parameter(Mandatory=$True)][datetime]$expirationdate,
        [Parameter(Mandatory=$True)][string]$SAM,
        [Parameter(Mandatory=$True)][string]$SMTPServer,
        [Parameter(Mandatory=$True)][string]$MailFrom
    )

    If (@(0,1) -contains $Days)
    {
        $SendNotice = $True
        $subject = "FINAL PASSWORD CHANGE NOTIFICATION - Your network password will expire in less than 24 hours."
        $body = "----Final Password Change Notice----`n`n"
        $body += "Your network password is due to expire within the next 24 hours.`n`n"
        write-output ("$days Day Notice sent to $SAM. Password expiration date: $expirationdate")
    }
    ElseIf (@(2,3,7,14) -contains $Days)
    {
        $SendNotice = $True
        $subject = "PASSWORD CHANGE NOTIFICATION - Your network password will expire in $days days."
        $body = "----$days Day Password Change Notice----`n`n"
        $body += "Your network password is due to expire in $days days.`n`n"
        write-output ("$days Day Notice sent to $SAM. Password expiration date: $expirationdate (in $days days)")
    }

    If ($SendNotice)
    {
        $body += "Please change your password before the expiration date to ensure you do not lose network access due to an expired password. `n`n"
        $body += "`n`n"
        $body += "To change your password, please close all open programs and press Ctrl-Alt-Del then choose `"Change Password`" from the list. `n`n"
        $body += "If you are unable to change your password, please contact the Help Desk. `n`n"
        $body += "*This is an automated message, please do not reply. Any replies will not be delivered.* `n`n"

        Send-MailMessage -To $usermail -From $mailfrom -Subject $subject -Body $body -SmtpServer $smtpserver
    }
    Else
    {
        #Write-output ("Notice not sent to $SAM. Password expiration date: $expirationdate (in $days days)")
    }
}

Function Send-AllNotices {
    <#
    .SYNOPSIS
    Main process.  Collects user accounts, calculates password expiration dates and passes the value along with user information to the send-notice function.
    
    .DESCRIPTION
    
    .EXAMPLE
    Send-AllNotices -ADGroupExclusion "Test Group" -MailFrom "noreply@email.com" -smtpserver "server.domain.local"
    
    .NOTES
    Title: Send-AllNotices
    Date Created : 2017-05-01   
    Last Edit: 2017-12-29
    Author : Andrew Ellis
    GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
    #>
    
    Param (
        [string]$ADGroupExclusion,
        [Parameter(Mandatory=$true)][string]$MailFrom,
        [Parameter(Mandatory=$true)][string]$smtpserver
    )

    $ServiceAccounts = Get-ADGroupMember -Identity $ADGroupExclusion -ErrorAction Stop
    $Users = Get-ADUser -Filter {(enabled -eq $true -and passwordneverexpires -eq $false)} -properties samaccountname, name, mail, msDS-UserPasswordExpiryTimeComputed -ErrorAction Stop | 
        Select-Object samaccountname, name, mail, msDS-UserPasswordExpiryTimeComputed

    #Filter users
    If ($ADGroupExclusion){
        $Users = $Users | Where-Object {
            $_.'msDS-UserPasswordExpiryTimeComputed' -and
            $_.Mail -and $_.SamAccountName -and
            $ServiceAccounts.SamAccountName -notcontains $_.SamAccountName
        } | Sort-Object -Property 'msDS-UserPasswordExpiryTimeComputed'
    }
    Else {
        $Users = $Users | Where-Object {
            $_.'msDS-UserPasswordExpiryTimeComputed' -and
            $_.Mail -and $_.SamAccountName
        } | Sort-Object -Property 'msDS-UserPasswordExpiryTimeComputed'
    }

    #Loop through users and send notices
    $Users | foreach-object {
        $Expirationdate = [datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed')
        $Expirationdays = ($Expirationdate - (Get-Date)).Days
        
        Send-Notice -usermail $_.Mail -days $ExpirationDays -expirationdate $expirationdate -SAM $_.SamAccountName -SMTPServer $smtpserver -MailFrom $mailfrom
    }
}

#Start logging.
Start-Logging -logdirectory "C:\ScriptLogs\SendPasswordNotices" -logname "SendPasswordNotices" -LogRetentionDays 30

#Start function
Send-AllNotices -ADGroupExclusion "Test Group" -MailFrom "noreply@email.com" -smtpserver "server.domain.local"

#Stop logging.
Stop-Transcript
