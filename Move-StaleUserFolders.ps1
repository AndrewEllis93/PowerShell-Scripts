###########################################################
#
# AUTHOR  : PowerMonkey500
#
# This script will scan all first-level sub-folders of the specified BasePath to find the most recent LastWriteTime in each one (recursively). This is really intended for user folders.
# Any folder that does not contain any items modified over the threshold (in days) will be moved to the DisabledPath you specify.
# If you just want to see which folders are stale, comment out the "OldDirs"loop at the end of the script, and uncomment the Out-Gridview section. Or you could replace Out-GridView with Export-CSV.
#
###########################################################

###Customization###
$Threshold = -180 #Must be negative.
$BasePath = "\\opshome\users"
$DisablePath = "\\opshome\users\DISABLE"
###################

$OldDirs = @()
$ActiveDirs = @()
$FailDirs = @()

#Get all parent (home) folders
$Dirs = Get-ChildItem $BasePath -Directory | Where {$_.FullName -notlike "$DisablePath*"}

$Dirs | % {
    $Fail = $False

    #Find the most recently modified item
    $FileTree = Get-ChildItem -Path $_.FullName -Recurse -Force | Sort-Object LastWriteTime -Descending
    #$SizeMB = ($FileTree | Measure-Object -property length -Sum).Sum / 1MB
    $LatestFile = $FileTree | Select-Object -First 1

    #Create object for output
    $FolderInfo = New-Object -TypeName PSObject
    $FolderInfo | Add-Member -MemberType NoteProperty -Name "ParentFolder" -Value $_.FullName
    $FolderInfo | Add-Member -MemberType NoteProperty -Name "LatestFile" -Value $LatestFile.FullName
    $FolderInfo | Add-Member -MemberType NoteProperty -Name "LastWriteTime" -Value $LatestFile.LastWriteTime
    #$FolderInfo | Add-Member -MemberType NoteProperty -Name "SizeMB" -Value $null
    
    #If there was no "most recently modified file", test the path. 
    #If we can't access the path (access denied), it throws a warning.
    #If we CAN access the path, just set the last modified time to that of the parent folder.
    If (!$FolderInfo.LastWriteTime){
        If (Test-Path $_.FullName) {
            $FolderInfo.LastWriteTime = $_.LastWriteTime
            $FolderInfo.LatestFile = $_.FullName
        }
        Else {
            $Fail = $True
            $FolderInfo.LastWriteTime = $Null
            $FolderInfo.LatestFile = $Null
        }
    }
    
    #Console outputs and build arrays.
    If ($Fail) {
        Write-Warning ("WARNING: Unable to enumerate " + $FolderInfo.ParentFolder + ".")
        $FailDirs += $FolderInfo
    }

    If ($FolderInfo.LastWriteTime -and $FolderInfo.LastWriteTime -lt ((get-date).AddDays($Threshold))){
        Write-Output ("Old directory found at " + $FolderInfo.ParentFolder + ". Last write time is " + $FolderInfo.LastWriteTime)
        $OldDirs += $FolderInfo
    } 
    ElseIf ($FolderInfo.LastWriteTime) {
    Write-Output ("Active directory found at " + $FolderInfo.ParentFolder + ". Last write time is " + $FolderInfo.LastWriteTime)
        $ActiveDirs += $FolderInfo
    }
}

#Sort by last modified, just for organization.
$FailDirs = $FailDirs | Sort LastWriteTime
$OldDirs = $OldDirs | Sort LastWriteTime
$ActiveDirs = $ActiveDirs | Sort LastWriteTime

<#
#Loop through all old directories and move them to disable folder.
$OldDirs | % {
    Write-Output ("Moving " + $_.ParentFolder + " to disable folder...")
    Move-Item $_.ParentFolder -Destination $Disablepath
}
#>

<#
#Show the results in a popup.
$FailDirs | Out-GridView
$OldDirs | Out-GridView
$ActiveDirs | Out-GridView
#>