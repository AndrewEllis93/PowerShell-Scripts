$Dir = (Read-Host "Enter CSV export directory (with trailing slash)") + "GPOs\"
$GPOs = get-gpo -All
$AllGPOs = @()

If (!(Test-Path $Dir)){mkdir $Dir -Force | Out-Null}

Write-Output "Exporting GPOs..."
ForEach ($GPO in $GPOs) {
    $GPO.DisplayName = $GPO.DisplayName.Replace('/','')
    $AllGPOs += $GPO.DisplayName
    $Path = $Dir + $GPO.DisplayName + ".HTML"
    Get-GPOReport -Name $GPO.DisplayName -ReportType HTML -Path $Path
    }
$AllGPOs = $AllGPOs | Sort-Object
$AllGPOs | out-file ($Dir + "AllGPOs.txt")

Write-Output "Exporting GPO links..."
$OUs = Get-ADOrganizationalUnit -Filter * | Sort {-join ($_.distinguishedname[($_.distinguishedname.length-1)..0])}
$OutputArray = @()
$OUs | % {
    $Inheritance = Get-GPInheritance -Target $_.DistinguishedName
    #$Inheritance.Path
    #$Inheritance.GpoLinks.DisplayName -join ", "
    #$Inheritance.GpoLinks.Order -join ", "

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
$OutputArray | Export-CSV ($Dir+"GPOLinks.csv") -NoTypeInformation