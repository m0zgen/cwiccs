
# Collext installed features
function checkFeatures
{

    if ($isAdmin)
    {
         $installedFeatures = Get-WindowsFeature -ComputerName $hostName | Where-Object { $_.Installed -match $True }

        foreach ( $feat in $installedFeatures ) {
            regularMsg -msg "$( $feat.DisplayName )"
            infoMsg -msg "installed - (INFO)`n"
            bindReportArray -arrType "features" -Name "$( $feat.Path )" -state "Installed" -status "INFO"
        }
    }
    elseif ($admin -or $elevate)
    {
        # Can using -NoExit for debug
        sendInfoToTerminal "You can get features list only from 'Run As Administrator' prompt"
        bindReportArray -arrType "features" -Name "Need elevated" -state "0" -status "WARNING"
    }
    else
    {
        sendInfoToTerminal "You can get features list only from 'Run As Administrator' prompt"
        bindReportArray -arrType "features" -Name "Need elevated" -state "0" -status "WARNING"
    }


} 



