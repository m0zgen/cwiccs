
# Collect installed features
function collectFeatures
{
    $installedFeatures = Get-WindowsFeature -ComputerName $hostName | Where-Object { $_.Installed -match $True }
    foreach ( $feat in $installedFeatures ) {
        regularMsg -msg "$( $feat.DisplayName )"
        infoMsg -msg "installed - (INFO)`n"
        bindReportArray -arrType "features" -Name "$( $feat.Path )" -state "Installed" -status "INFO"
    }
}

function checkFeatures
{
    # Exclude checking features for Win 10        
    # infoMsg -msg "$( $osName ) - $( $osVersion )`n"

    if ($osVersion -eq "server") {
        $osTypeClient = $false
        if ($isAdmin)
            {
                collectFeatures
            }
            elseif ($admin -or $elevate)
            {
                collectFeatures
            }
            else
            {
                sendInfoToTerminal "You can get features list only from 'Run As Administrator' prompt"
                bindReportArray -arrType "features" -Name "Need elevated" -state "0" -status "WARNING"
            }
    }
    elseif ($osVersion -eq "client") {
        $osTypeClient = $true
        regularMsg -msg "$( $osVersion ) - does not has server features"
        infoMsg -msg "(INFO)`n"
    }
    else {
        warningMsg -msg "Unsupported Windows Version - Error`n"
    }

} 



