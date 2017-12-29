####################################################
#
# Title: Move-StaleUserFolders
# Date Created : 2017-12-28
# Last Edit: 2017-12-29
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# This script will scan all first-level sub-folders of the specified BasePath to find the most recent LastWriteTime in each one (recursively). This is really intended for user folders.
# Any folder that does not contain any items modified over the threshold (in days) will be moved to the DisabledPath you specify.
#
###########################################################

Function Move-StaleUserFolders {
    <#
    .SYNOPSIS
    This script will scan all first-level sub-folders of the specified BasePath to find the most recent LastWriteTime in each one (recursively). This is really intended for user folders.
    Any folder that does not contain any items modified over the threshold (in days) will be moved to the DisabledPath you specify.

    .DESCRIPTION

    .EXAMPLE
    Move-StaleUserFolders -ReportOnly $True -BasePath "\\SERVER\users\" -DisablePath "\\SERVER\users\disable"

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    Title: Move-StaleUserFolders
    Date Created : 2017-12-28
    Last Edit: 2017-12-29
    Author : Andrew Ellis
    GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
    #>

    Param (
        [int]$Threshold = 180,
        [Parameter(Mandatory=$true)][string]$BasePath,
        [Parameter(Mandatory=$true)][string]$DisablePath,
        [bool]$ReportOnly = $False
    )

    #Remove the trailing slash if present. 
    If ($BasePath -like "*\"){$BasePath = $BasePath.substring(0,($BasePath.Length-1))}
    If ($DisablePath -like "*\"){$DisablePath = $DisablePath.substring(0,($DisablePath.Length-1))}

    #Declarations
    $OldDirs = @()
    $ActiveDirs = @()
    $FailDirs = @()

    #Get all parent (home) folders
    $Dirs = Get-ChildItem $BasePath -Directory | Where-Object {$_.FullName -notlike "$DisablePath*"}

    $Dirs | ForEach-Object {
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
        If ($FolderInfo.LastWriteTime -and $FolderInfo.LastWriteTime -lt ((get-date).AddDays(($Threshold * -1)))){
            Write-Output ("Old directory found at " + $FolderInfo.ParentFolder + ". Last write time is " + $FolderInfo.LastWriteTime)
            $OldDirs += $FolderInfo
        } 
        ElseIf ($FolderInfo.LastWriteTime) {
        Write-Output ("Active directory found at " + $FolderInfo.ParentFolder + ". Last write time is " + $FolderInfo.LastWriteTime)
            $ActiveDirs += $FolderInfo
        }
    }

    If (!$ReportOnly){
        #Sort by last modified, just for organization.
        #$FailDirs = $FailDirs | Sort-Object LastWriteTime
        #$OldDirs = $OldDirs | Sort-Object LastWriteTime
        #$ActiveDirs = $ActiveDirs | Sort-Object LastWriteTime

        #Loop through all old directories and move them to disable folder.
        $OldDirs | ForEach-Object {
            Write-Output ("Moving " + $_.ParentFolder + " to disable folder...")
            Move-Item $_.ParentFolder -Destination $Disablepath
        }
    }
}

Function Start-Logging {
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
    Get-ChildItem -Path $LogDirectory -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $RetentionDate -and $_.Name -like "*.log"} | Remove-Item -Force
} 

#Start logging.
Start-Logging -LogDirectory "C:\ScriptLogs\Move-StaleUserFolders" -LogName "Move-StaleUserFolders" -LogRetentionDays 30

#Start function.
Move-StaleUserFolders -ReportOnly $True -BasePath "\\SERVER\users\" -DisablePath "\\SERVER\users\disable"

#Stop logging.
Stop-Transcript