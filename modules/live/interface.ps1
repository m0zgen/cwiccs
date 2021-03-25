# Online checking
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
#            "Unable to download MyDoc.doc from https://cwiccs.org."
#        }
#        catch {
#            "An error occurred that could not be resolved."
#            Write-Host ($_ | ConvertTo-Json)
#        }

        catch
        {
            Write-Host "Invalid web token"
            # Write-Host ($_ | ConvertTo-Json)
        }
    }
    else
    {
        Write-Host "Web serer is down!"
    }
}
else
{
    warningMsg -msg "App token does not defined in the cwiccs.json`n"
}

function createJSON
{
    param(
        [Parameter(Mandatory = $true)]$fileName,
        [Parameter(Mandatory = $true)]$data
    )

    # Save to json
    try
    {
        # JSON Data saver
        $path = $jsonFolder + "\" + $osUUID # + "\" + $fileName
        $dataFile = $path + "\" + $fileName
        createFolder $path

        $data | ConvertTo-Json | Set-Content -Path $dataFile
    }
    catch
    {
        Write-Host "Can't write report $path file - Permission denied"
    }
}

function sendJSON
{
    param(
        [Parameter(Mandatory = $true)]$data,
        [Parameter(Mandatory = $true)]$apiLink
    )

    $header = @{"X-CWiCCS"=$config.App_Name}
    $header += @{"Authorization"="Token " + $config.App_Token}
    $header += @{"UUID"=$osUUID}

    $body = $data | ConvertTo-Json

    # Invoke-WebRequest "http://192.168.10.19:8000/test-post"  -Body $body -Method 'POST' -Headers $header

#    if (checkHttpStatus -url $config.App_Web_Server)
#    {
        $uri = $config.App_Web_Server + $apiLink
        Invoke-RestMethod -Method post -ContentType 'Application/Json' -Headers $header -Body $body -Uri $uri
#    }
#    else
#    {
#        Write-Host "Web serer is down!"
#    }

}

function genJSONObjects
{
    param(
        [Parameter(Mandatory = $true)]$arrayData
    )

    $jsonObject = $arrayData | ForEach-Object {
        New-Object -TypeName PSObject -Property @{
            'name' = $_.Name
            'status' = $_.Status
            'device' = $onlineId.id
            'state' = $_.State
        }
    }

    return $jsonObject
}

function bindJSON
{
    # Generate web api JSON objects
    $jsonDisks = $diskInfo | ForEach-Object {
        New-Object -TypeName PSObject -Property @{
            'name' = $_.Name
            'total_size' = $_.'Total(GB)'
            'free_size' = $_.'Free(GB)'
            'device' = $onlineId.id
        }
    }

    sendJSON -data $jsonDisks -apiLink "/api/disks/"
    if ($saveonlinejson)
    { createJSON -data $jsonDisks -fileName "disks-web.json" }

    $jsonFeatures = genJSONObjects -arrayData $reportFeatures
    sendJSON -data $jsonFeatures -apiLink "/api/features/"
    if ($saveonlinejson)
    { createJSON -data $jsonFeatures -fileName "features-web.json" }

    $jsonLocalAuditPolicies = genJSONObjects -arrayData $localAuditPolicy
    sendJSON -data $jsonLocalAuditPolicies -apiLink "/api/local-audit-policies/"
    if ($saveonlinejson)
    { createJSON -data $jsonLocalAuditPolicies -fileName "local-audit-policies-web.json" }
}


# Bind, Send JSON data to WEB server
regularMsg -msg "Web id status "
if ($onlineId -eq $null)
{

    infoMsg -msg "Not provided`n"
}
else
{
    infoMsg -msg "OK`n"
    bindJSON
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

# Generate JSON data in the UUID computer folder in the reports folder
if ($savereportjson)
{
    createJSON -data $diskInfo -fileName "disks.json"
    createJSON -data $reportFeatures -fileName "features.json"
    createJSON -data $localAuditPolicy -fileName "local-audit-policies.json"
    createJSON -data $localPasswordPolicy -fileName "local-password-policies.json"
    createJSON -data $localRegistryPolicy -fileName "local-registry-policies.json"
    createJSON -data $localUsers -fileName "local-users.json"
    createJSON -data $reportPorts -fileName "ports.json"
    createJSON -data $reportRequiredServices -fileName "requred-services.json"
    createJSON -data $reportRestrictedServices -fileName "restricted-services.json"
    createJSON -data $reportBaseSettings -fileName "settings.json"
    createJSON -data $reportSoft -fileName "soft.json"
    createJSON -data $deviceId -fileName "device.json"
}


Write-Host $onlineId.id
Write-Host $deviceId

Write-Host $reportSoft
$reportSoft = $reportSoft | Add-Member -NotePropertyMembers @{device=$onlineId.id} -PassThru
Write-Host $reportSoft
$body2 = $reportSoft | ConvertTo-Json
Write-Host $body2
#Invoke-RestMethod -Method post -ContentType 'Application/Json' -Headers $header -Body $body2 -Uri https://cwiccs.org/api/disks/

# 710e2bdb5ef4ee274fa4dac12ea50f1d7bca96ea

# getGPOProfile

# Temporary section
# ----------------
# start $htmlReport
# Write-Host $reportSoft.Count

$jsonLocalAuditPolicies | ConvertTo-Json

