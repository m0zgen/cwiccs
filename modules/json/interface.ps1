# Online
if (!$config.App_Token -eq "")
{
    if (checkHttpStatus -url $config.App_Web_Server)
    {
        $header = @{"X-CWiCCS"=$config.App_Name}
        $header += @{"Authorization"="Token " + $config.App_Token}
        $header += @{"UUID"=$osUUID}
        $body = $deviceId | ConvertTo-Json

        $uri = $config.App_Web_Server + "/api/devices/"

        try
        {
            $onlineId = Invoke-RestMethod -Method post -ContentType 'Application/Json' -Headers $header -Body $body -Uri $uri
        }
#        catch [System.Net.WebException],[System.IO.IOException] {
#            "Unable to download MyDoc.doc from http://www.contoso.com."
#        }
#        catch {
#            "An error occurred that could not be resolved."
#
#            Write-Host ($_ | ConvertTo-Json)
#        }

        catch
        {
            Write-Host "Invalid web token"
            # Write-Host ($_ | ConvertTo-Json)
        }
    }
}

# Generate web api JSON objects
$jsonDiskInfo = $diskInfo | ForEach-Object {
    New-Object -TypeName PSObject -Property @{
        'name' = $_.Name
        'total_size' = $_.'Total(GB)'
        'free_size' = $_.'Free(GB)'
        'device' = $onlineId.id
    }
}


# Send JSON data to WEB server
if ($online)
{
    regularMsg -msg "Web id status "
    if ($onlineId -eq $null)
    {

        infoMsg -msg "Not provided`n"
    }
    else
    {
        infoMsg -msg "OK`n"
    }




    # sendJSON -data $localUsers -fileName "localUsers.json" -apiLink "/local-users"

    #$localUsers | ConvertTo-Json | Set-Content -Path "c:\tmp\localUsers.json"
    #$diskInfo | ConvertTo-Json | Set-Content -Path "c:\tmp\diskInfo.json"
    #$localPasswordPolicy | ConvertTo-Json | Set-Content -Path "c:\tmp\localPasswordPolicy.json"
    #$localAuditPolicy | ConvertTo-Json | Set-Content -Path "c:\tmp\localAuditPolicy.json"
    #$localRegistryPolicy | ConvertTo-Json | Set-Content -Path "c:\tmp\localRegistryPolicy.json"
    #$reportBaseSettings | ConvertTo-Json | Set-Content -Path "c:\tmp\reportBaseSettings.json"
    #$reportFeatures | ConvertTo-Json | Set-Content -Path "c:\tmp\reportFeatures.json"
    #$reportRequiredServices | ConvertTo-Json | Set-Content -Path "c:\tmp\reportRequrementServices.json"
    #$reportRestrictedServices | ConvertTo-Json | Set-Content -Path "c:\tmp\reportRestrictedServices.json"
    #$reportPorts | ConvertTo-Json | Set-Content -Path "c:\tmp\reportPorts.json"
    #$reportSoft | ConvertTo-Json | Set-Content -Path "c:\tmp\reportSoft.json"

    # DONE - отправлять токен в хедерсах попутно с каждым json
    # TODO - идетнтификатор машины (устройства) в хедерсах к каждому файлу отправлять
    # TODO - добавить  cwiccs.config
}
