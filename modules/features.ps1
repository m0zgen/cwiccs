
# Collext installed features
function checkFeatures
{

    $installedFeatures = Get-WindowsFeature -ComputerName $hostName | Where-Object { $_.Installed -match $True }

    foreach ( $feat in $installedFeatures ) {
        regularMsg -msg "$( $feat.DisplayName )"
        infoMsg -msg "installed - (INFO)`n"
        bindReportArray -arrType "features" -Name "$( $feat.Path )" -state "Installed" -status "INFO"
    }
} 



