
# Ports
# -------------------------------------------------------------------------------------------\
function checkPorts
{

    $listenPorts = @(Get-NetTCPConnection -State Listen | Select localPort | sort-object -Property localPort -unique)
    $listens = Get-NetTCPConnection -State Listen

    $portListObject = @()
    $listenListObject = @()

    ForEach ($allowedPort in $ports.allowed_ports)
    {
        $portListObject += ,$allowedPort.LocalPort
    }

    ForEach ($listen in $listens)
    {
        $listenListObject += ,$listen.LocalPort
    }

    [System.Collections.ArrayList]$allowedArray = $portListObject
    [System.Collections.ArrayList]$listenArray = $listenListObject
    $listenArray = $listenArray | Sort-Object -Unique

    ForEach ($listen in $listens)
    {

        ForEach ($allowedPort in $ports.allowed_ports)
        {
            if ( $allowedPort.LocalPort.toString().Contains($listen.LocalPort.toString()))
            {
                regularMsg -msg "Found "
                infoMsg "Allowed listen port - $( $listen.LocalPort )`n"
                #
                bindReportArray -arrType "ports" -Name "Allowed listen port" -state "$( $listen.LocalPort )" -status "OK"
            }
        }
    }

    ForEach ($listen in $listens)
    {

        if ($listen.LocalPort -ge 49152 -and $listen.LocalPort -le 65535)
        {
            regularMsg -msg "Found "
            infoMsg "Allowed listen port (from range) - $( $listen.LocalPort )`n"
            #
            bindReportArray -arrType "ports" -Name "Allowed listen port (from range)" -state "$( $listen.LocalPort )" -status "OK"
            #
            $listenArray.Remove($listen.LocalPort)
        }
    }

    # compare $portListObject $listenListObject | select -ExpandProperty inputobject
    $c = Compare-Object -ReferenceObject $allowedArray -DifferenceObject $listenArray

    foreach ($badPort in $c)
    {

        if ($badPort.SideIndicator -eq "=>")
        {
            regularMsg -msg "Found "
            errorMsg -msg "Unknown listen port is $( $badPort.InputObject )`n"
            #
            bindReportArray -arrType "ports" -Name "Unknown listen port" -state "$( $badPort.InputObject )" -status "FAIL"
        }

    }
}