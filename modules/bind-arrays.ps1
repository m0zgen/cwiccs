

# Convert object to array
function ToArray
{
    begin
    {
        $output = @();
    }
    process
    {
        $output += $_;
    }
    end
    {
        return ,$output;
    }
}

# Bind global arrays
function bindReportArray
{
    param(
        [String]$arrType,
        [String]$name,
        [String]$state,
        [String]$status
    )

    $obj = New-Object -TypeName PSObject
    $obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $name
    $obj | Add-Member -MemberType NoteProperty -Name "State" -Value $state
    $obj | Add-Member -MemberType NoteProperty -Name "Status" -value $status

    if ($arrType -eq "required")
    {
        $reportRequiredServices += $obj
    }
    elseif ($arrType -eq "restricted")
    {
        $reportRestrictedServices += $obj
    }
    elseif ($arrType -eq "ports")
    {
        $reportPorts += $obj
    }
    elseif ($arrType -eq "soft")
    {
        # warningMsg -msg "SOFT CHECKING"
        $reportSoft += $obj
    }
    elseif ($arrType -eq "base")
    {
        $reportBaseSettings += $obj
    }
    elseif ($arrType -eq "features")
    {
        $reportFeatures += $obj
    }
    elseif ($arrType -eq "passwordPolicy")
    {
        $localPasswordPolicy += $obj
    }
    elseif ($arrType -eq "auditPolicy")
    {
        $localAuditPolicy += $obj
    }
    elseif ($arrType -eq "regPolicy")
    {
        $localRegistryPolicy += $obj
    }
    else
    {

        warningMsg -msg "Warning "
        errorMsg -msg "Can't bind report array - $arrType`n"
    }
}