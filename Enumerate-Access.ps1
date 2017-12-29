Function Enumerate-Access {
    <#
    .SYNOPSIS
    This is a simple Powershell function to retreive all NTFS permissions recursively from a file path.

    .DESCRIPTION
    IncludeInherited defaults to False. This will only show excplicit ACL entries, excluding the top-level path which will always show all permissions.
    Depth is unlimited unless specified.
    Paths should not contain trailing slashes.

    .EXAMPLE
    Enumerate-Access -Path '\\SERVER\Share' -Depth 10 -IncludeInherited $True

    .LINK

    .NOTES
    #>

    Param(
        [Parameter(Mandatory=$true)][string]$Path,
        [int]$Depth,
        [boolean]$IncludeInherited=$False
    )

    If ($Path -like "*\"){Throw "Path cannot have a trailing slash."}
    If (!(Test-Path $Path)){Throw "Path was not reachable."}

    If ($Depth){$Tree = Get-Childitem $Path -recurse -Depth $Depth -Directory}
    Else {$Tree = Get-Childitem $Path -recurse -Directory}

    $Output = @()
    $Iteration = 1
    $Total = $Tree.Count

    #Top-level ACL
    $TopLevelACL = $Path | Get-Acl
    $FullName = (Get-Item $Path).FullName
    $Index = 0
    $TopLevelACL.Access.IdentityReference.Value | ForEach-Object {
        $OutputObj = New-Object -TypeName PSObject
        $OutputObj | Add-Member -Name FullName -MemberType NoteProperty -Value $FullName
        $OutputObj | Add-Member -Name Owner -MemberType NoteProperty -Value $TopLevelACL.Owner
        $OutputObj | Add-Member -Name IdentityReference -MemberType NoteProperty -Value ($TopLevelACL.Access.IdentityReference.Value[$Index])
        $OutputObj | Add-Member -Name FileSystemRights -MemberType NoteProperty -Value ($TopLevelACL.Access.FileSystemRights[$Index])
        $OutputObj | Add-Member -Name AccessControlType -MemberType NoteProperty -Value ($TopLevelACL.Access.AccessControlType[$Index])
        $OutputObj | Add-Member -Name IsInherited -MemberType NoteProperty -Value ($TopLevelACL.Access.IsInherited[$Index])
        $OutputObj | Add-Member -Name InheritanceFlags -MemberType NoteProperty -Value ($TopLevelACL.Access.InheritanceFlags[$Index])

        $Output += $OutputObj
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
                    $OutputObj = New-Object -TypeName PSObject
                    $OutputObj | Add-Member -Name FullName -MemberType NoteProperty -Value $FullName
                    $OutputObj | Add-Member -Name Owner -MemberType NoteProperty -Value $ACL.Owner
                    $OutputObj | Add-Member -Name IdentityReference -MemberType NoteProperty -Value ($ACL.Access.IdentityReference.Value[$Index])
                    $OutputObj | Add-Member -Name FileSystemRights -MemberType NoteProperty -Value ($ACL.Access.FileSystemRights[$Index])
                    $OutputObj | Add-Member -Name AccessControlType -MemberType NoteProperty -Value ($ACL.Access.AccessControlType[$Index])
                    $OutputObj | Add-Member -Name IsInherited -MemberType NoteProperty -Value ($ACL.Access.IsInherited[$Index])
                    $OutputObj | Add-Member -Name InheritanceFlags -MemberType NoteProperty -Value ($ACL.Access.InheritanceFlags[$Index])

                    $Output += $OutputObj
                    $Index++
                }
            }
        }
        Else {
            $ACL.Access.IdentityReference.Value | ForEach-Object {
                $OutputObj = New-Object -TypeName PSObject
                $OutputObj | Add-Member -Name FullName -MemberType NoteProperty -Value $FullName
                $OutputObj | Add-Member -Name Owner -MemberType NoteProperty -Value $ACL.Owner
                $OutputObj | Add-Member -Name IdentityReference -MemberType NoteProperty -Value ($ACL.Access.IdentityReference.Value[$Index])
                $OutputObj | Add-Member -Name FileSystemRights -MemberType NoteProperty -Value ($ACL.Access.FileSystemRights[$Index])
                $OutputObj | Add-Member -Name AccessControlType -MemberType NoteProperty -Value ($ACL.Access.AccessControlType[$Index])
                $OutputObj | Add-Member -Name IsInherited -MemberType NoteProperty -Value ($ACL.Access.IsInherited[$Index])
                $OutputObj | Add-Member -Name InheritanceFlags -MemberType NoteProperty -Value ($ACL.Access.InheritanceFlags[$Index])

                $Output += $OutputObj
                $Index++
            }
        }
        $PercentComplete = [math]::Round((($Iteration / $Total) * 100),1)
        If ($PercentComplete -lt 100){Write-Progress -Activity "Scanning permissions" -Status "$PercentComplete% Complete ($Iteration/$Total)" -PercentComplete $PercentComplete}
        Else {Write-Progress -Activity "Scanning permissions" -Status "$PercentComplete% Complete ($Iteration/$Total)" -PercentComplete $PercentComplete -Completed}
        $Iteration++
    }
    Return $Output
}