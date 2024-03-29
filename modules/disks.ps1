function getDiskInfo
{
    # Created by Mohammed A. Wasay
    # Edited by ALI TAJRAN / ALITAJRAN.com
     
    # Name the server where this needs to be run

    # Check Total Capacity of the Drive
    $TCapacity =
    @{
        Expression = { "{0,19:n2}" -f ($_.Capacity / 1GB) };
        Name       = 'Total Capacity (GB)';
    }
     
    # Freespace to be displayed in GB
    $Freespace =
    @{
        Expression = { "{0,15:n2}" -f ($_.FreeSpace / 1GB) };
        Name       = 'Free Space (GB)';
    }
     
    # Percentage value of the free space
    $PercentFree =
    @{
        Expression = { [int]($_.Freespace * 100 / $_.Capacity) };
        Name       = 'Free (%)'
    }
     
    # # Calculation # TODO: shall be $hostname instead $localhost for Arministrators need be checking procedure
    # $allDisksInfo = Get-CimInstance -namespace "root/cimv2" -computername $localhost -query "SELECT Name, Capacity, FreeSpace FROM Win32_Volume WHERE Capacity > 0 and (DriveType = 2 OR DriveType = 3)" |
    # # Display of values
    # Select-Object -Property Name, $TCapacity, $Freespace, $PercentFree  | Sort-Object 'Free (%)' -Descending

    # Calculation # TODO: shall be $hostname instead $localhost for Arministrators need be checking procedure
    $allDisksInfo = Get-CimInstance -namespace "root/cimv2" -query "SELECT Name, Capacity, FreeSpace FROM Win32_Volume WHERE Capacity > 0 and (DriveType = 2 OR DriveType = 3)" |
    # Display of values
    Select-Object -Property Name, $TCapacity, $Freespace, $PercentFree  | Sort-Object 'Free (%)' -Descending

    # Main
    $diskInfo = $allDisksInfo | ForEach-Object {

        # Write-Host $_.Name
        $totalGB = clearSpace($_."Total Capacity (GB)")
        $freeGB = clearSpace($_."Free Space (GB)")
        $freePercent = clearSpace($_."Free (%)")

        New-Object -TypeName PSObject -Property @{
            'Name' = $_.Name
            'Total(GB)' = $totalGB
            'Free(GB)' = $freeGB
            'Free(%)' = $freePercent
        }
    }

    regularMsg -msg "Disk info (sorted by free space percentage)...`n"
    foreach ($disk in $diskInfo)
    {
        # Write-Host $disk.Name
        # Write-Host $disk."Total(GB)"
        # Write-Host $disk."Free(GB)"
        # Write-Host $disk."Free(%)"

        if (!$disk.Name.Contains("\\?\")) {
            regularMsg -msg "Disk "
            infoMsg -msg "$( $disk.Name ) - Total $( $disk.'Total(GB)' )GB, Free $( $disk.'Free(GB)' )GB, Free $( $disk.'Free(%)' )%`n"    
        }
    }
    ###
}

function getCDDrives {

    param(
        [Parameter(Mandatory = $true)]$diskLetter
    )

    @(Get-WmiObject win32_logicaldisk -filter 'DriveType=5' |
        ForEach-Object { 
            $cd = $_.DeviceID + "\"
            Write-Host -AAAAA  $_.DeviceID -BBBBB $diskLetter
            # $_.DeviceID
            if ($cd -eq $diskLetter) {
                Write-Host TRUE
                return $true
            }
            else {
                return $false
                Write-Host FALSE
            }
        }
    )
}
function getHddInfo {
    
    #$fss = Get-PSDrive -PSProvider FileSystem
    
    $fss = Get-PSDrive -PSProvider FileSystem | Select-Object Name, Root, DisplayRoot, @{Name='Used';Expression={$_.Used/1GB}}, @{Name='Free';Expression={$_.Free/1GB}}

    $diskInfo = $fss | ForEach-Object {
        
        # exlude readonly and network devices
        if ($null -eq $_.DisplayRoot) {

            $f = [math]::Round($_.Free,2)
            $u = [math]::Round($_.Used,2)
            # total size
            $t = $f + $u
            # calculate persents

            if (!$null -eq $_.Free) {
                $p = [math]::Round($f / $t * 100,2)
            } else {
                $p = "0"
            }

            $r = $_.Root

            # if (getCDDrives -diskLetter $r) {
            #     $r = $r + " CD Drive"
            # }

            @(Get-WmiObject win32_logicaldisk -filter 'DriveType=5' |
                ForEach-Object { 
                    $cd = $_.DeviceID + "\"
                    if ($cd -eq $r) {
                        $r = $r + " (CD Drive)"
                    }
                }
            )

            # Write-Host $_.Name - $f - $u - $t - $p2 "%" - $_.Root

            New-Object -TypeName PSObject -Property @{
                'Name' = $r
                'Total(GB)' = $t -replace ',','.'
                'Used(GB)' = $u -replace ',','.'
                'Free(GB)' = $f -replace ',','.'
                'Free(%)' = $p -replace ',','.'
            }

        } 
    
    }

    regularMsg -msg "Disk info (sorted by disk letters)...`n"
    foreach ($disk in $diskInfo)
    {
        if (!$disk.Name.Contains("\\?\")) {
            regularMsg -msg "Disk "
            infoMsg -msg "$( $disk.Name ) - Total $( $disk.'Total(GB)' )GB, Used $( $disk.'Used(GB)' )GB, Free $( $disk.'Free(GB)' )GB, Free $( $disk.'Free(%)' )%`n"    
        }
    }
    
}