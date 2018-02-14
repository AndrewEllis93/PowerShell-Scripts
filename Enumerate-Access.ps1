####################################################
#
# Title: Enumerate-Access
# Date Created : 2017-12-28
# Last Edit: 2017-12-29
# Author : Andrew Ellis
# GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
#
# This function will spit back all of the permissions of a specified folder, recursively. You can choose to return inherited permissions or not. I wrote this specifically to show each and every ACL entry on a separate line. # # It's really useful for finding where a group or user is being used in NTFS ACLs. This helped us get rid of mail-enabled security groups by discovering each place that they were being used in NTFS ACLs so we could replace them. 
# In most cases you won't want it to return inherited permissions (it doesn't by default) so you don't get a TON of redundant output, just the explicit ACL entries. 
# It will generate a lot of disk activity on the target server because it scans the entire file system of the folder specified.
#
####################################################

Function Enumerate-Access {
    <#
    .SYNOPSIS
    This is a simple Powershell function to retreive all NTFS permissions recursively from a file path.

    .DESCRIPTION
    IncludeInherited defaults to False. This will only show excplicit ACL entries, excluding the top-level path which will always show all permissions.
    Depth is unlimited unless specified.

    .EXAMPLE
    Enumerate-Access -Path '\\SERVER\Share' -Depth 10 -IncludeInherited

    .LINK
    https://github.com/AndrewEllis93/PowerShell-Scripts

    .NOTES
    Author : Andrew Ellis
    GitHub: https://github.com/AndrewEllis93/PowerShell-Scripts
    #>

    [cmdletbinding()]
    Param(
        [Parameter(Mandatory=$true)][string]$Path,
        [int]$Depth,
        [switch]$IncludeInherited=$False
    )

    #Remove the trailing slash if present. 
    If ($Path -like "*\"){
        $Path = $Path.substring(0,($Path.Length-1))
    }
    If (!(Test-Path $Path)){
        Throw "Path was not reachable."
    }

    #This part now has long (>260 character) path support, thanks to /u/vBurak 
    #https://www.reddit.com/r/sysadmin/comments/7moj1w/there_was_some_interest_in_my_scripts_so_i/du18hf0/
    Write-Verbose "Getting file tree..."
    $LiteralPath = "\\?\" + $Path
    If ($Depth){
        $Tree = Get-Childitem -LiteralPath $LiteralPath -Recurse -Depth $Depth -Directory -ErrorAction
    }
    Else {
        $Tree = Get-Childitem -LiteralPath $LiteralPath -Recurse -Directory
    }

    $Output = [System.Collections.ArrayList]@()
    $Iteration = 1
    $Total = $Tree.Count

    #Top-level ACL (always shows inherited permissions)
    $TopLevelACL = $Path | Get-Acl
    $FullName = (Get-Item $Path).FullName
    $Index = 0
    $TopLevelACL.Access.IdentityReference.Value | ForEach-Object {
        $OutputObj = [PSCustomObject]@{}
        $OutputObj | Add-Member -Name FullName -MemberType NoteProperty -Value $FullName.Replace('\\?\','')
        $OutputObj | Add-Member -Name Owner -MemberType NoteProperty -Value $TopLevelACL.Owner
        $OutputObj | Add-Member -Name IdentityReference -MemberType NoteProperty -Value ($TopLevelACL.Access.IdentityReference.Value[$Index])
        $OutputObj | Add-Member -Name FileSystemRights -MemberType NoteProperty -Value ($TopLevelACL.Access.FileSystemRights[$Index])
        $OutputObj | Add-Member -Name AccessControlType -MemberType NoteProperty -Value ($TopLevelACL.Access.AccessControlType[$Index])
        $OutputObj | Add-Member -Name IsInherited -MemberType NoteProperty -Value ($TopLevelACL.Access.IsInherited[$Index])
        $OutputObj | Add-Member -Name InheritanceFlags -MemberType NoteProperty -Value ($TopLevelACL.Access.InheritanceFlags[$Index])

        $Output.Add($OutputObj) > $null
        $Index++
    }

    #Recursive ACL
    $Tree | ForEach-Object {

        $FullName = $_.FullName
        $ACL = $_ | Get-ACL

        $Index = 0

        If ($IncludeInherited -eq $False) {
            $ACL.Access.IdentityReference.Value | ForEach-Object {
                If ($ACL.Access.IsInherited[$Index] -eq $False){
                    $OutputObj = [PSCustomObject]@{}
                    $OutputObj | Add-Member -Name FullName -MemberType NoteProperty -Value $FullName.Replace('\\?\','')
                    $OutputObj | Add-Member -Name Owner -MemberType NoteProperty -Value $ACL.Owner
                    $OutputObj | Add-Member -Name IdentityReference -MemberType NoteProperty -Value ($ACL.Access.IdentityReference.Value[$Index])
                    $OutputObj | Add-Member -Name FileSystemRights -MemberType NoteProperty -Value ($ACL.Access.FileSystemRights[$Index])
                    $OutputObj | Add-Member -Name AccessControlType -MemberType NoteProperty -Value ($ACL.Access.AccessControlType[$Index])
                    $OutputObj | Add-Member -Name IsInherited -MemberType NoteProperty -Value ($ACL.Access.IsInherited[$Index])
                    $OutputObj | Add-Member -Name InheritanceFlags -MemberType NoteProperty -Value ($ACL.Access.InheritanceFlags[$Index])
                    
                    $Output.Add($OutputObj) > $null
                    $Index++
                }
            }
        }
        Else {
            $ACL.Access.IdentityReference.Value | ForEach-Object {
                $OutputObj = [PSCustomObject]@{}
                $OutputObj | Add-Member -Name FullName -MemberType NoteProperty -Value $FullName.Replace('\\?\','')
                $OutputObj | Add-Member -Name Owner -MemberType NoteProperty -Value $ACL.Owner
                $OutputObj | Add-Member -Name IdentityReference -MemberType NoteProperty -Value ($ACL.Access.IdentityReference.Value[$Index])
                $OutputObj | Add-Member -Name FileSystemRights -MemberType NoteProperty -Value ($ACL.Access.FileSystemRights[$Index])
                $OutputObj | Add-Member -Name AccessControlType -MemberType NoteProperty -Value ($ACL.Access.AccessControlType[$Index])
                $OutputObj | Add-Member -Name IsInherited -MemberType NoteProperty -Value ($ACL.Access.IsInherited[$Index])
                $OutputObj | Add-Member -Name InheritanceFlags -MemberType NoteProperty -Value ($ACL.Access.InheritanceFlags[$Index])

                $Output.Add($OutputObj) > $null
                $Index++      
            }
        }
        $PercentComplete = [math]::Round((($Iteration / $Total) * 100),1)
        If ($PercentComplete -lt 100){
            Write-Progress -Activity "Scanning permissions" -Status "$PercentComplete% Complete ($Iteration/$Total)" -PercentComplete $PercentComplete
        }
        Else {
            Write-Progress -Activity "Scanning permissions" -Status "$PercentComplete% Complete ($Iteration/$Total)" -PercentComplete $PercentComplete -Completed
        }
        $Iteration++
    }
    Return $Output
}

$ACL = Enumerate-Access -Path "C:\Test"
$ACL | Export-CSV C:\TestACL.csv -NoTypeInformation -Encoding UTF8