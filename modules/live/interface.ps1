# 
$contentType = 'Application/Json; charset=utf-8'
# Functions
# -------------------------------------------------------------------------------------------\

# Deprecated
function checkEntry
{

    param(
        [Parameter(Mandatory = $true)]$oID
    )

    $header = @{"Authorization"="Token " + $config.App_Token}

    $uri = $config.App_Web_Server + "/api/entries/"

    if ($osPSVersion -lt 6) {
        $data = Invoke-RestMethod -Method get -ContentType $contentType -Headers $header -Uri $uri
    }
    else {
        $data = Invoke-RestMethod -Method get -ContentType $contentType -Headers $header -Uri $uri -SkipCertificateCheck
    }

    if ($data)
    {
        if (($data | Foreach {$_.id}) -contains $oID)
        {
            return $true
        }
        else
        {
            return $false
        }
    }
    else
    {
        return $false
    }

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

        $data | ConvertTo-Json | Set-Content -Path $dataFile -Encoding utf8
    }
    catch
    {
        Write-Host "Can't write report $path file - Permission denied"
    }
}

function convertStrDateToUTC
{
    param(
        [Parameter(Mandatory = $true)]$strDate
    )

    try
    {
        $dt = [System.DateTime]$strDate
        $offset = [TimeZoneInfo]::Local | Select BaseUtcOffset
        $result = $dt.toUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffK')
        return $result
    }
    catch
    {
        return $strDate
    }


}
function sendJSON
{
    param(
        [Parameter(Mandatory = $true)]$data,
        [Parameter(Mandatory = $true)]$apiLink,
        [Parameter(Mandatory = $true)]$fileName
    )

    $header = @{"X-CWiCCS"=$config.App_Name}
    $header += @{"Authorization"="Token " + $config.App_Token}
    $header += @{"UUID"=$osUUID}

    $body = $data | ConvertTo-Json

    if ($saveonlinejson)
    {
        createJSON -data $data -fileName $fileName
    }

    # Invoke-WebRequest "http://192.168.10.20:8000/test-post"  -Body $body -Method 'POST' -Headers $header

    #    if (checkHttpStatus -url $config.App_Web_Server)
    #    {
    $uri = $config.App_Web_Server + $apiLink

    try
    {
        
        if ($osPSVersion -lt 6) {
            $resp = Invoke-RestMethod -Method post -ContentType $contentType -Headers $header -Body $body -Uri $uri
        }
        else {
            $resp = Invoke-RestMethod -Method post -ContentType $contentType -Headers $header -Body $body -Uri $uri -SkipCertificateCheck
        }
        # $rep.Dispose()
#       write-host $resp - OK
    }
    catch
    {
        Write-Host "Error send JSON data to web server `n"

        if ($debug)
        {

            debugMsg -msg "Interface SEND JSON DATA"
            $_.Exception.Response
            $result = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($result)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();

            Write-Host $responseBody
        }

    }

    #    }
    #    else
    #    {
    #        Write-Host "Web serer is down!"
    #    }

}

function genJSONObjectFeatures {
    param(
        [Parameter(Mandatory = $true)]$arrayData
    )
    
    # Empty or not
    if ($arrayData) {
        $jsonObject = genJSONObjects -arrayData $arrayData
        return $jsonObject
    }
    else {
        $jsonObject = New-Object -TypeName PSObject -Property @{
            'entry' = $entryId.id
            'name' = 'NoN'
            'state' = 'NoN'
            'status' = 'INFO'
        }

        return $jsonObject
    }

    # if ($osTypeClient) { }
}

function genJSONObjectDisk {
    param(
        [Parameter(Mandatory = $true)]$arrayData
    )
    
    $jsonObject = $arrayData | ForEach-Object {

        $tSize = $_.'Total(GB)'
        $tSize = $tSize
        $fSize = $_.'Free(GB)'
        $fSize = $fSize

        New-Object -TypeName PSObject -Property @{
            'entry' = $entryId.id
            'name' = $_.Name
            'total_size' = $tSize
            'free_size' = $fSize
#            'device' = $onlineId.id
        }
    }

    return $jsonObject
}

function genJSONObjectPorts {
    param(
        [Parameter(Mandatory = $true)]$arrayData
    )
    
    $jsonObject = $arrayData | ForEach-Object {
        New-Object -TypeName PSObject -Property @{
            'entry' = $entryId.id
            'port' = $_.State
            'status' = $_.Status
        }
    }

    return $jsonObject
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
            #            'device' = $onlineId.id
            'entry' = $entryId.id
            'state' = $_.State
        }
    }

    return $jsonObject
}

# Online checking
# -------------------------------------------------------------------------------------------\

if (!$config.App_Token -eq "")
{
    if (checkHttpStatus -url $config.App_Web_Server)
    {
        $header = @{"X-CWiCCS"=$config.App_Name}
        $header += @{"Authorization"="Token " + $config.App_Token}
        $header += @{"UUID"=$osUUID}
        $body = $deviceId | ConvertTo-Json

        $uriDev = $config.App_Web_Server + "/api/devices/"
        $uriEnt = $config.App_Web_Server + "/api/entries/"

        try
        {
            if ($osPSVersion -lt 6) {
                $onlineId = Invoke-RestMethod -Method post -ContentType $contentType -Headers $header -Body $body -Uri $uriDev
            }
            else {
                $onlineId = Invoke-RestMethod -Method post -ContentType $contentType -Headers $header -Body $body -Uri $uriDev -SkipCertificateCheck
            }

            if ($null -eq $onlineId)
            {
                infoMsg -msg "Online ID not provided`n"
            }
            else
            {
                infoMsg -msg "Inline Id retrieved - OK`n"

                $jsonEntryOID = $onlineId | ForEach-Object {
                    New-Object -TypeName PSObject -Property @{
#                        'id' = $_.id
                        'device' = $_.id
                    }
                }

                $jsonEntry = $jsonEntryOID | ConvertTo-Json
                if ($osPSVersion -lt 6) {
                    $entryId = Invoke-RestMethod -Method post -ContentType $contentType -Headers $header -Body $jsonEntry -Uri $uriEnt
                }
                else {
                    $entryId = Invoke-RestMethod -Method post -ContentType $contentType -Headers $header -Body $jsonEntry -Uri $uriEnt -SkipCertificateCheck
                }
                infoMsg -msg "Entry Id retrieved - OK`n"

                if ($debug)
                {
                    debugMsg -msg "Interface JSON - Online and Entry IDs"
                    Write-Host "Online ID - $onlineId"
                    Write-Host "Entry oID - $jsonEntryOID"
                    Write-Host "Entry ID - $entryId"
                }

            }


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

            if ($debug)
                {
                    debugMsg -msg "Web token validation"
                    Write-Host ($_ | ConvertTo-Json)
                }
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

function bindJSON
{
    # Generate web api JSON objects

    # Deprecated
#    if (checkEntry -oID $onlineId.id)
#    {
#        regularMsg -msg "Notice: "
#        infoMsg -msg "Device alredy registered. `n"
#    }
#    else
#    {
#        # Send data
#    }

#    $jsonEntry = $onlineId | ForEach-Object {
#        New-Object -TypeName PSObject -Property @{
#            'id' = $_.id
#            'device' = $_.id
#        }
#    }
#
#    sendJSON -data $jsonEntry -apiLink "/api/entries/" -fileName "entries-web.json"

    if ($debug)
    {
        Write-Host $entryId.id
    }

    $jsonHDD = genJSONObjectDisk -arrayData $diskInfo
    sendJSON -data $jsonHDD -apiLink "/api/disks/" -fileName "disks-web.json"

    $jsonPorts = genJSONObjectPorts -arrayData $reportPorts
    sendJSON -data $jsonPorts -apiLink "/api/ports/" -fileName "ports-web.json"

    $jsonLocalAuditPolicies = genJSONObjects -arrayData $localAuditPolicy
    sendJSON -data $jsonLocalAuditPolicies -apiLink "/api/local-audit-policies/" -fileName "local-audit-policies-web.json"

    $jsonLocalPasswordPolicies = genJSONObjects -arrayData $localPasswordPolicy
    sendJSON -data $jsonLocalPasswordPolicies -apiLink "/api/local-password-policies/" -fileName "local-password-policies-web.json"

    $jsonLocalRegistryPolicies = genJSONObjects -arrayData $localRegistryPolicy
    sendJSON -data $jsonLocalRegistryPolicies -apiLink "/api/local-password-policies/" -fileName "local-registry-policies-web.json"

    $jsonRequiredServices = genJSONObjects -arrayData $reportRequiredServices
    sendJSON -data $jsonRequiredServices -apiLink "/api/required-services/" -fileName "reqired-services-web.json"

    $jsonRestrictedServices = genJSONObjects -arrayData $reportRestrictedServices
    sendJSON -data $jsonRestrictedServices -apiLink "/api/restricted-services/" -fileName "restricted-services-web.json"

    $jsonBaseSettings = genJSONObjects -arrayData $reportBaseSettings
    sendJSON -data $jsonBaseSettings -apiLink "/api/settings/" -fileName "settings-web.json"

    $jsonSoft = genJSONObjects -arrayData $reportSoft
    sendJSON -data $jsonSoft -apiLink "/api/software/" -fileName "soft-web.json"
    
    ##

    $jsonLocalUsers = $localUsers | ForEach-Object {

        $pwdExOn = convertStrDateToUTC -strDate $_.'Password Expiry Date'

        New-Object -TypeName PSObject -Property @{
            'entry' = $entryId.id
            'name' = $_.Name
            'full_name' = $_.'Full Name'
            'description' = $_.'Description'
            'domain' = $_.'Domain'
            'password_expires_on' = $pwdExOn
            'is_disabled' = $_.'Disabled'
            'is_locked_out' = $_.'LockOut'
            'is_password_required' = $_.'Password Required'
            'is_password_expired' = $_.'Password Expires'
            'status' = $_.'Status'
        }
    }

    if ($debug)
    {
        debugMsg -msg "Local users data"
        Write-Host $jsonLocalUsers
    }
    sendJSON -data $jsonLocalUsers -apiLink "/api/local-users/" -fileName "local-users-web.json"

    # Write-Host Is Workstation - $osTypeClient
    $jsonFeatures = genJSONObjectFeatures -arrayData $reportFeatures
    sendJSON -data $jsonFeatures -apiLink "/api/features/" -fileName "features-web.json"
    
    # Transaction Finality
    # Object for fun :)
    $jsonFinality  = New-Object -TypeName PSObject -Property @{
        'entry_id' = $entryId.id
        'online_id' = $onlineId.device_id
        'pc_name' = $onlineId.name
        'hello_from_sa' = 'Sys-Admins POWER! Peace!'
        'site' = 'https://cwiccs.org'
        'is_complete' = 'true'
    }
    $uriFinality = "/api/entries/" + $entryId.id + "/set_complete/"
    sendJSON -data $jsonFinality -apiLink $uriFinality -fileName "finality-web.json"
}


# Bind, Send JSON data to WEB server
regularMsg -msg "- Web id status "
if ($null -eq $onlineId)
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

if ($debug)
{

    debugMsg -msg "Interface JSON"

    Write-Host $onlineId.id
    Write-Host $deviceId

    Write-Host $reportSoft
    $reportSoft = $reportSoft | Add-Member -NotePropertyMembers @{ device = $onlineId.id } -PassThru
    Write-Host $reportSoft
    $body2 = $reportSoft | ConvertTo-Json
    Write-Host $body2
    #Invoke-RestMethod -Method post -ContentType $contentType -Headers $header -Body $body2 -Uri https://cwiccs.org/api/disks/

    $jsonLocalAuditPolicies | ConvertTo-Json

}

#Write-Host $jsonEntry
#Write-Host $jsonLocalPasswordPolicies

