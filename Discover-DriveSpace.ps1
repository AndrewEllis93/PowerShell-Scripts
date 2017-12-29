####################################################
#
# Title: Discover-DriveSpace
# Date Created : 2017-12-28
# Last Edit: 2017-12-29
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# This function gets all your servers in AD and dumps the drives with sizes and remaining free space to a CSV (DriveSpace.csv). 
# It also export some other files - Pingable.txt, PingFail.txt, and Servers.csv. Those should be self-explanatory.
#
####################################################

#Function declarations
Function Discover-DriveSpace {
    <#
    .SYNOPSIS
    This function gets all your servers in AD and dumps the drives with sizes and remaining free space to a CSV (DriveSpace.csv). 
    It also export some other files - Pingable.txt, PingFail.txt, and Servers.csv. Those should be self-explanatory.

    .DESCRIPTION

    .EXAMPLE
    Discover-DriveSpace -OutputPath "C:\temp" -DomainController "DC1.domain.local"

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    #>

    Param (
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [string]$DomainController
    )

    $Output = @()
    $Pingable = @()
    $PingFail = @()
    $Iteration = 0

    #Remove trailing slash if present.
    If ($OutputPath -like "*\"){$OutputPath = $OutputPath.substring(0,($OutputPath.Length -1))}

    #Create the directory if it does not exist. 
    If (!(Test-Path $OutputPath)){
        Write-Output ("Output directory not found. Creating folder at $OutputPath...")
        mkdir $OutputPath -Force | Out-Null
    }
    
    #Get servers from AD, using domain controller specified if specified.
    Import-Module ActiveDirectory
    Write-Output "Getting servers from AD..."
    If (!$DomainController){$ADServers = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | Where-Object {$_.Enabled -eq "True"} | Select-Object Name | Sort-Object Name}
    Else {$ADServers = Get-ADComputer -Server $DomainController -Filter {OperatingSystem -Like "Windows Server*"} | Where-Object {$_.Enabled -eq "True"} | Select-Object Name | Sort-Object Name}

    $Count = $ADServers.Count
    
    Clear-Host
    "`n`n`n`n`n`n`n`n"
    
    ForEach ($Server in $ADServers){
        #Show progress
        $PercentComplete = [math]::Round((($Iteration / $Count) * 100),0)
        If ($PercentComplete -lt 100){Write-Progress -Activity ("Getting disk info from " + $Server.Name + "..") -Status "$PercentComplete% Complete ($Iteration/$Count)" -PercentComplete $PercentComplete}
        Else {Write-Progress -Activity ("Getting disk info from" + $Server.Name + "..") -Status "$PercentComplete% Complete ($Iteration/$Count)" -PercentComplete $PercentComplete -Completed}
    
        #Tests ping. Only tries a second time if first ping fails.
        If (Test-Connection -ComputerName $Server.Name -Count 1 -ErrorAction SilentlyContinue){$Ping = $True}
        ElseIf (Test-Connection -ComputerName $Server.Name -Count 1 -ErrorAction SilentlyContinue){$Ping = $True}
        Else {$Ping = $False}
    
        #If pingable...
        If ($Ping){
    
            #Add to pingable servers array
            $Pingable += $Server.Name
    
            #Get disk info from WMI
            $DiskInfo = Get-WMiObject -ComputerName $Server.Name win32_logicaldisk -Filter "drivetype=3 AND NOT Volumename LIKE '%page%'" -ErrorAction SilentlyContinue
    
            #Create an object for each disk returned from WMI
            ForEach ($Disk in $DiskInfo){
                $Size = [math]::Round(($Disk.Size/1gb),2)
                $FreeSpace = [math]::Round(($Disk.FreeSpace/1gb),2)
                $PercentFree = [math]::Round((($Disk.FreeSpace * 100.0)/$Disk.Size),2)
     
                $Obj = New-Object -TypeName PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "SystemName" -Value $Disk.SystemName
                $Obj | Add-Member -MemberType NoteProperty -Name "DeviceID" -Value $Disk.DeviceID
                $Obj | Add-Member -MemberType NoteProperty -Name "SizeGB" -Value $Size
                $Obj | Add-Member -MemberType NoteProperty -Name "FreeSpaceGB" -Value $FreeSpace
                $Obj | Add-Member -MemberType NoteProperty -Name "PercentFree" -Value $PercentFree
                $Obj | Add-Member -MemberType NoteProperty -Name "Label" -Value $Disk.Volumename
     
                #Add to output array.
                $Output += $Obj
            }
        }
        Else {
            Write-Warning ("Ping failed for " + $Server.Name + ".")
            $PingFail += $Server.Name
        }
        $Iteration++
    }
    
    Write-Output ("Exporting files to $OutputPath...")
    $ADServers | ConvertTo-CSV -NoTypeInformation | Select-Object -Skip 1 | Out-File "$OutputPath\Servers.csv"
    $Pingable | Out-File "$OutputPath\Pingable.txt"
    $PingFail | Out-File "$OutputPath\PingFail.txt"
    $Output | Sort-Object SystemName,Drive | Export-CSV "$OutputPath\DriveSpace.csv" -NoTypeInformation

    Write-Output "Done."
}

#Call the function.
Discover-DriveSpace -OutputPath "C:\Temp" 