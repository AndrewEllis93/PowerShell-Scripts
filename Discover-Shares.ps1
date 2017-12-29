If (!$Path){$Path = Read-Host "Enter CSV export directory (with trailing slash)"}
If (!(Test-Path $Path)){mkdir $Path -Force | Out-Null}

Function Discover-Shares {
    <#
    .SYNOPSIS
    Written by Andrew Ellis
    Last edit: 2017-10-31

    This function discovers all Windows Servers from Active Directory and discovers their file shares using WMI.

    .DESCRIPTION
    The following are always excluded:
    - Admin shares
    - NETLOGON
    - SYSVOL
    - print$
    - prnproc$
    - ADMIN$

    FilterShares is enabled by default.
    Filter removes:
    - *Sophos*
    - *SMS*
    - Wsus*
    - SHARES
    - REMINST
    - *ClusterStorage$
    - *SCCM*

    .EXAMPLE
    Find-Shares -DomainController DC1 -FilterShares $True

    .LINK

    .NOTES
    #>

    param([boolean]$FilterShares = $True,
        [string]$DomainContoller)

    If (!$DomainController){$Servers = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | Where {$_.Name -notlike "ENTDP*"} | Sort Name}
    Else {$Servers = Get-ADComputer -Server $DomainContoller -Filter {OperatingSystem -Like "Windows Server*"} | Where {$_.Name -notlike "ENTDP*"} | Sort Name}
    $ServerCount = $Servers.Count
    $Iteration = 1

    $Output = @()
    $FailServers = @()

    $Servers | % {
        $Server = $_.Name

        $Fail = $False
        $WMI = $null

        Try {
            if ($FilterShares){
                $WMI = get-WmiObject -class Win32_Share -computer $_.Name -ErrorAction Stop | Where {`
                $_.Name -notlike "?$" -and `
                $_.Name -notlike "*Sophos*" -and `
                $_.Name -notlike "*SCCM*" -and `
                $_.Name -notlike "*ClusterStorage$" -and `
                $_.Name -notlike "SMS*" -and `
                $_.Name -notlike "Wsus*" -and `
                $_.Name -ne "ADMIN$" -and `
                $_.Name -ne "print$" -and `
                $_.Name -ne "prnproc$" -and `
                $_.Name -ne "NETLOGON" -and `
                $_.Name -ne "SYSVOL" -and `
                $_.Name -ne "SHARES" -and `
                $_.Name -ne "REMINST" -and `
                $_.Path -like "?:\*"}
            }
            Else {
                $WMI = get-WmiObject -class Win32_Share -computer $_.Name -ErrorAction Stop | Where {`
                $_.Name -notlike "?$" -and `
                $_.Path -like "?:\*"}
            }
        }
        Catch {
            $Fail = $True
            Write-Warning ($Server + " discovery failed.")
            Write-Error $Error[0]
        }

        If ($WMI){
            $WMI | % {
                $OutputObj = New-Object -TypeName PSObject
                $OutputObj | Add-Member -MemberType NoteProperty -Name 'Server' -Value $Server
                $OutputObj | Add-Member -MemberType NoteProperty -Name 'Share' -Value $_.Name
                $OutputObj | Add-Member -MemberType NoteProperty -Name 'Path' -Value $_.Path
                $OutputObj | Add-Member -MemberType NoteProperty -Name 'Description' -Value $_.Description

                $Output += $OutputObj
            }
        }

        If ($Fail){
        
            $FailServers += $_.Name

            $OutputObj = New-Object -TypeName PSObject
            $OutputObj | Add-Member -MemberType NoteProperty -Name 'Server' -Value $Server
            $OutputObj | Add-Member -MemberType NoteProperty -Name 'Share' -Value "FAIL"
            $OutputObj | Add-Member -MemberType NoteProperty -Name 'Path' -Value "FAIL"
            $OutputObj | Add-Member -MemberType NoteProperty -Name 'Description' -Value "FAIL"

            $Output += $OutputObj
        }

        $PercentComplete = [math]::Round((($Iteration / $ServerCount) * 100),0)
        If ($PercentComplete -lt 100){Write-Progress -Activity "Scanning AD servers for shares" -Status "$PercentComplete% Complete ($Iteration/$ServerCount)" -PercentComplete $PercentComplete}
        Else {Write-Progress -Activity "Scanning AD servers for shares" -Status "$PercentComplete% Complete ($Iteration/$ServerCount)" -PercentComplete $PercentComplete -Completed}
        $Iteration++
    }

    Return $Output
}

$Results = Discover-Shares -FilterShares $False
$Results | Export-CSV ($Path + "Shares.csv") -NoTypeInformation