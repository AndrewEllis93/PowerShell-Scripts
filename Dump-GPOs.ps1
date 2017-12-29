####################################################
#
# Title: Dump-GPOs
# Date Created : 2017-12-28
# Last Edit: 2017-12-29
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# This exports all of your GPOs' HTML reports, a CSV detailing all the GPO links, and a txt list of all the GPOs.
#
####################################################

Function Dump-GPOs {
     <#
    .SYNOPSIS
    This exports all of your GPOs' HTML reports, a CSV detailing all the GPO links, and a txt list of all the GPOs to the specified output directory.

    .DESCRIPTION

    .EXAMPLE
    Dump-GPOs -OutputDirectory "C:\temp"

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    Title: Dump-GPOs
    Date Created : 2017-12-28
    Last Edit: 2017-12-29
    Author : Andrew Ellis
    GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
    #>

    Param (
        [Parameter(Mandatory=$true)][String]$OutputDirectory
    )

    #Remove trailing slash if present.
    If ($OutputDirectory -like "*\"){$OutputDirectory = $OutputDirectory.substring(0,($OutputDirectory.Length-1))}

    $GPOs = get-gpo -All
    $AllGPOs = @()

    If (!(Test-Path $OutputDirectory)){mkdir $OutputDirectory -Force | Out-Null}

    ForEach ($GPO in $GPOs) {
        $GPO.DisplayName = $GPO.DisplayName.Replace('/','')
        $AllGPOs += $GPO.DisplayName
        Write-Output ("Exporting " + $OutputDirectory + "\" + $GPO.DisplayName + ".HTML...")
        $Path = $OutputDirectory + "\" + $GPO.DisplayName + ".HTML"
        Get-GPOReport -Name $GPO.DisplayName -ReportType HTML -Path $Path
        }
    $AllGPOs = $AllGPOs | Sort-Object
    Write-Output ("Exporting " + $OutputDirectory + "\AllGPOs.txt...")
    $AllGPOs | Out-File ($OutputDirectory + "\AllGPOs.txt")

    $OUs = Get-ADOrganizationalUnit -Filter * | Sort-Object {-join ($_.distinguishedname[($_.distinguishedname.length-1)..0])}
    $OutputArray = @()
    $OUs | ForEach-Object {
        $Inheritance = Get-GPInheritance -Target $_.DistinguishedName

        $GpoLinks = @()
        If ($Inheritance.GpoLinks.DisplayName){
            ForEach ($i in 0..($Inheritance.GpoLinks.DisplayName.Count -1)){
                $GpoLinks += $Inheritance.GpoLinks[$i].Order.toString() + ": " + $Inheritance.GpoLinks[$i].DisplayName
            }
        }

        $Obj = New-Object -TypeName PSObject
        $Obj | Add-Member -MemberType NoteProperty -Name "Path" -Value $Inheritance.Path
        $Obj | Add-Member -MemberType NoteProperty -Name "GpoLinks" -Value ($GpoLinks -join ", ")
        $OutputArray += $Obj
    }

    Write-Output ("Exporting " + $OutputDirectory + "\GPOLinks.csv...")
    $OutputArray | Export-CSV ($OutputDirectory+"\GPOLinks.csv") -NoTypeInformation
}

Dump-GPOs -OutputDirectory "C:\temp"