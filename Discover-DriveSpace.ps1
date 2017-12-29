If (!$Path){$Path = Read-Host "Enter CSV export directory (with trailing slash)"}
If (!(Test-Path $Path)){mkdir $Path -Force | Out-Null}

$Servers = Get-ADComputer -Filter {OperatingSystem -Like "Windows Server*"} | Sort Name

$Output = @()

foreach ($Computer in $Servers.Name){
    Write-Host "Connected to $computer"
    $Disks =  gwmi -computername $computer win32_logicaldisk -filter "drivetype=3" -ErrorAction SilentlyContinue
    ForEach ($disk in $disks){
        $Size = "{0:0.0}" -f ($disk.size/1gb)
        $Freespace = "{0:0.0}" -f ($disk.freespace/1gb)
        $Used = ([int64]$disk.size - [int64]$disk.freespace)
        $SpacedUsed = "{0:0.0}" -f ($used/1gb)
        $Percent = ($disk.freespace * 100.0)/$disk.size
        $Percent = "{0:0}%" -f $percent
 
        $Obj = ""|sort systemname | select systemname,drive,size,freespace,percent_free 
        $Obj.systemname = $Disk.systemname
        $Obj.drive = $Disk.deviceid
        $Obj.size = $Size
        $Obj.freespace = $FreeSpace
        $Obj.percent_free = $Percent
 
        $Output += $Obj
    }
}

$Output | sort systemname,drive | export-csv ($Path + "DriveSpace.csv") -notypeinformation