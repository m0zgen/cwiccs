#Requires -Version 2
<#

.SYNOPSIS
This is a Powershell script to check and fix secirity settings

.DESCRIPTION
Scitpt can use from everywhere. Required files / folders:
- config
- cwiccs.ps1

Available arguments
- cwiccs.ps1 [-autofix] [-report] [-elevate] [-admin] [-profile] <profilename> [-profilelist] [-help]
- [-elevate] and [-admin] arguments it is same (made for convenience)

.EXAMPLE
./cwiccs.ps1
./cwiccs.ps1 -report

#>

<#

Author: Yevgeniy Goncharov
Name: Check and Fix Windows and Control Configs and Security - CWiCCS (read as QUICKS) Framework
Purpose: Base Security Settings Windows Operation System Checker

#>

# Initial functions
# -------------------------------------------------------------------------------------------\

# -autofix - fixing all founded errors / incorrect system settings
param (
    [Switch]$autofix,
    [Switch]$report,
    [Switch]$json,
    [Switch]$elevate,
    [Switch]$admin,
    [Switch]$help,
    [Switch]$debug,
    [Switch]$profilelist,
    [array]$profile
)

# Init script location
# Get script location path
function getScriptDirPath
{
    $scriptInvocation = (Get-Variable MyInvocation -Scope 1).Value
    return Split-Path $scriptInvocation.MyCommand.Path
}

$global:scriptFolder = $( getScriptDirPath )
$scriptName = $MyInvocation.MyCommand.Name
# cd $scriptFolder

# Initial functions / messages / warnings / etc


. "$scriptFolder\modules\common.ps1"
. "$scriptFolder\modules\vars.ps1"

. "$scriptFolder\modules\bind-arrays.ps1"
. "$scriptFolder\modules\initial-html.ps1"

. "$scriptFolder\modules\os.ps1"
. "$scriptFolder\modules\localusers.ps1"
. "$scriptFolder\modules\checkPorts.ps1"
. "$scriptFolder\modules\getInstalledSoftware.ps1"
. "$scriptFolder\modules\reg-handler.ps1"
. "$scriptFolder\modules\uac.ps1"
. "$scriptFolder\modules\svc-handler.ps1"
. "$scriptFolder\modules\ntp.ps1"
. "$scriptFolder\modules\disks.ps1"

. "$scriptFolder\modules\features.ps1"

# Initial procedures
# -------------------------------------------------------------------------------------------\
if (!$debug) {
    checkPowerShellVersion    
}


# Profiles (script folder location depensed)
# -------------------------------------------------------------------------------------------\
if ($profilelist)
{
    $profiles = Get-ChildItem -Path config\profiles -Recurse -Directory -Force -ErrorAction SilentlyContinue | Select-Object Name
    foreach ($profile in $profiles)
    {
        Write-Host $profile.Name
    }
    Exit 1
}

# Binding profiles
. "$scriptFolder\modules\bind-profiles.ps1"

# Common / Service Functions
# -------------------------------------------------------------------------------------------\

if ($help)
{   
    . "$scriptFolder\modules\help.ps1"
    # pass data from module
    Write-Host $helpDetails
    # and them exit
    Exit 1
}

# If -autofux using as script argument
if ($autofix)
{
    echo "Autofix is TRUE"
    if (!$isAdmin)
    {
        infoMsg -msg "INFO "
        warningMsg -msg "-autofix can be using with ELEVATED PRIVILEGED ONLY!`n"
        infoMsg -msg "Bye Bye!"
        Break Script
    }
}

function sendInfoToTerminal($info)
{
    infoMsg -msg "INFO "
    warningMsg -msg "$info`n"
}

function statusDomainMemeber
{
    regularMsg -msg "Computer status: "
    if ($isDomain) {
        
        infoMsg -msg "Domain member`n"; regularMsg -msg "Domain name: "; infoMsg -msg "$domainName`n"
        
        # if ($domainRole -eq 5) {
        #     warningMsg -msg "This is PDC (PDC - does not has local users info)`n"
        # }
    } 
    else { infoMsg -msg "Workgroup member`n" }
}


# Extra
# -------------------------------------------------------------------------------------------\

$extra = Get-ChildItem -Filter ex_*.ps1 -Path extra -Recurse -File -Force -ErrorAction SilentlyContinue | Select-Object Name

if ($extra) {
    
    foreach ($ex in $extra)
    { 
        $name = $ex.Name
        . ".\extra\$name"
    }
    $isExtra = 1    
} else {
    $isExtra = 0
}

# Processing
# -------------------------------------------------------------------------------------------\

# SMB
# -------------------------------------------------------\

# Reference
# https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3

# Method from registry
function disableSMB1
{
    if ($autofix)
    {
        setRegHKLMBOOLValue -regKeyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -subKeyName "SMB1" -enabled $false
        checkSMB1
    }
    else
    {
        cmAutofixNote
    }
}

# Method from comandlet
function disableSMB2_3
{
    if ($autofix)
    {
        Set-SmbServerConfiguration -EnableSMB2Protocol $false -Confirm:$false # or -Force
        checkSMB2
    }
    else
    {
        cmAutofixNote
    }


}

function checkSMB1
{

    regularMsg -msg "SMBv1 is "
    if (isRegHKLMValue -regKeyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -subKeyName "SMB1")
    {
        errorMsg -msg "Enabled - Fail "
        disableSMB1
        #
        bindReportArray -arrType "base" -Name "SMBv1" -state "Enabled" -status "FAIL"
    }
    else
    {
        infoMsg -msg "Disabled - OK`n"
        #
        bindReportArray -arrType "base" -Name "SMBv1" -state "Disabled" -status "OK"
    }
}

function checkSMB2
{

    regularMsg -msg "SMBv2 is "
    if (isRegHKLMValue -regKeyPath "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -subKeyName "SMB2")
    {
        errorMsg -msg "Enabled - Fail "
        disableSMB2_3
        #
        bindReportArray -arrType "base" -Name "SMBv2" -state "Enabled" -status "FAIL"
    }
    else
    {
        infoMsg -msg "Disabled - OK`n"
        #
        bindReportArray -arrType "base" -Name "SMBv2" -state "Disabled" -status "OK"
    }

}

# GPO
# -------------------------------------------------------\

$ScriptBlock = {
    function exportGPO
    {
        param($p)
        secedit.exe /export /cfg $p > $null
        # Write-Host $p
    }
}

function Parse-SecPol($policyFile)
{
    # secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $policyFile -raw
    [regex]::Matches($contents, "(?<=\[)(.*)(?=\])") | %{
        $title = $_
        [regex]::Matches($contents, "(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | %{
            $section = new-object psobject
            $_.value -split "\r\n" | ?{ $_.length -gt 0 } | %{
                $value = [regex]::Match($_, "(?<=\=).*").value
                $name = [regex]::Match($_, ".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}

function getAuditPolicy
{
    $SecPool = Parse-SecPol -policyFile $secPolExported

    bindReportArray -arrType "auditPolicy" -Name "Audit Account Logon" -state $SecPool.'Event Audit'.AuditAccountLogon -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit Account Manage" -state $SecPool.'Event Audit'.AuditAccountManage -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit DS Access" -state $SecPool.'Event Audit'.AuditDSAccess -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit Logon Events" -state $SecPool.'Event Audit'.AuditLogonEvents -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit Object Access" -state $SecPool.'Event Audit'.AuditObjectAccess -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit Policy Change" -state $SecPool.'Event Audit'.AuditPolicyChange -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit Privilege Use" -state $SecPool.'Event Audit'.AuditPrivilegeUse -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit Process Tracking" -state $SecPool.'Event Audit'.AuditProcessTracking -status "INFO"
    bindReportArray -arrType "auditPolicy" -Name "Audit System Events" -state $SecPool.'Event Audit'.AuditSystemEvents -status "INFO"


    ##
    regularMsg -msg "Audit Account Logon "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditAccountLogon ) - INFO`n"
    regularMsg -msg "Audit Account Manage "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditAccountManage ) - INFO`n"
    regularMsg -msg "Audit DS Access "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditDSAccess ) - INFO`n"
    regularMsg -msg "Audit Logon Events "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditLogonEvents ) - INFO`n"
    regularMsg -msg "Audit Object Access "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditObjectAccess ) - INFO`n"
    regularMsg -msg "Audit Policy Change "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditPolicyChange ) - INFO`n"

    regularMsg -msg "Audit Privilege Use "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditPrivilegeUse ) - INFO`n"
    regularMsg -msg "Audit Process Tracking "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditProcessTracking ) - INFO`n"
    regularMsg -msg "Audit System Events "; infoMsg -msg "$( $SecPool.'Event Audit'.AuditSystemEvents ) - INFO`n"
    ##

}

#if ($admin -or $elevate)
#{
#    Start-Process -FilePath PowerShell -ArgumentList "-ExecutionPolicy Bypass -Command & {$ScriptBlock exportGPO -p $secPolExported}" -verb RunAs
#}

function checkAuditPolicy
{
    if ($isAdmin)
    {
        secedit.exe /export /cfg $secPolExported > $null
        getAuditPolicy
    }
    elseif ($admin -or $elevate)
    {
        # Can using -NoExit for debug
        Start-Process -FilePath PowerShell -ArgumentList "-ExecutionPolicy Bypass -Command & {$ScriptBlock exportGPO -p $secPolExported}" -verb RunAs
        getAuditPolicy
    }
    else
    {
        sendInfoToTerminal "You can get GPO audit policies only from 'Run As Administrator' prompt"
        bindReportArray -arrType "auditPolicy" -Name "Need elevated" -state "0" -status "WARNING"
    }
}


# Data from CMD - data from gpo profile
$passParamsTable = @{

  "Minimum password age (days)" = "MinimumPasswordAge"
  "Maximum password age (days)" = "MaximumPasswordAge"
  "Minimum password length" = "MinimumPasswordLength"
  "Length of password history maintained" = "PasswordHistorySize"
  "Lockout threshold" = "LockoutBadCount"
  "Lockout duration (minutes)" = "LockoutDuration"
  "Lockout observation window (minutes)" = "ResetLockoutCount"

 }


# https://stackoverflow.com/questions/60117943/powershell-script-to-report-account-lockout-policy-settings
function checkPassPols
{
    # If not -admin or -elevated argument
    $out = $env:TEMP + "\net-ass.txt"
    $( net accounts ) | Out-File $out
    $in = get-content $out

    foreach ($line in $in)
    {
        if ($line -like "*password*" -or $line -like "*lockout*" -and $line -notlike "machine\*" -and $line -notlike "require*")
        {
            
            $policy = $line.substring(0,$line.IndexOf(":"))

            $values = $line.substring($line.IndexOf(":") + 1, $line.Length - ($line.IndexOf(":") + 1))
            $values = $values.trim() -split ","
            $splitted = ($values -split ":")[0]
            # $localPasswordPolicy.Add($policy,$splitted) #output edited version
            # bindReportArray -arrType "passwordPolicy" -Name $policy -state $splitted -status "INFO"

            # regularMsg -msg "$policy "
            # infoMsg -msg "$splitted`n"

            # Verify matching

            $passParamsTable.keys | ForEach-Object {
                # Write-Output "$_"
                # Write-Output "Value = $($passParamsTable[$_])"

                if ($policy -eq "$_") {
                    # warningMsg -msg "MATCH"

                    foreach ($gpoparam in $gpo.password_policy)
                    {
                        if ($gpoparam.Name -eq $($passParamsTable[$_])) {

                            # regularMsg -msg "$policy ( GPO name - $( $gpoparam.Name ) ) "
                            regularMsg -msg "$policy "

                            if ($splitted -eq $gpoparam.State) {
                                infoMsg -msg "$splitted - OK`n"
                                bindReportArray -arrType "passwordPolicy" -Name $policy -state $splitted -status "OK"
                            } else {
                                errorMsg -msg "FAIL ($( $gpoparam.State ) required, current state - $splitted)`n"
                                bindReportArray -arrType "passwordPolicy" -Name $policy -state $splitted -status "FAIL"
                            }


                        }
                    
                    }

                }
            
            }

        }
    }
}


# Testing
function getGPOProfile
{

    $passParamsTable.keys | ForEach-Object {
        Write-Output "$_"
        Write-Output "Value = $($passParamsTable[$_])"

        foreach ($gpoparam in $gpo.password_policy)
        {

            if ($gpoparam.Name -eq $($passParamsTable[$_])) {
                warningMsg -msg "MATCH"
            }

        }

        Write-Output '----------'
    }

}


function checkRegPols
{
    foreach ($key in $gpo.registry_policy)
    {
        regularMsg -msg "$( $key.GPO_Name ) "
        # $currentState = (isRegHKLMValue -regKeyPath $key.Path -subKeyName $key.Value_Name)

        $p = "HKLM:\" + $key.Path

        if (Test-RegistryValue -Path $p -ValueName $key.Value_Name)
        {
            $currentState = (Get-ItemProperty -Path $p -Name $key.Value_Name).$( $key.Value_Name )

            # If byte array
            if ($currentState -is [array])
            {
                # If null or not
                if ($currentState.GetUpperBound(0) -eq 0)
                {
                    $currentState = $currentState -as [int]
                    $currentState = 0
                }
            }

            if (($currentState -eq $key.Value) -or (([string]::IsNullOrEmpty($key.Value)) -and ([string]::IsNullOrEmpty($currentState))))
            {
                infoMsg -msg "OK`n"
                if ( [string]::IsNullOrEmpty($key.Value))
                {
                    $key.Value = "empty"
                }
                bindReportArray -arrType "regPolicy" -Name $key.GPO_Name -state "$( $key.Value )" -status "OK"
            }
            else
            {
                errorMsg -msg "FAIL ($( $key.Value ) required, current state $( $currentState ))`n"
                # TODO: FIXING
                bindReportArray -arrType "regPolicy" -Name $key.GPO_Name -state "$( $currentState ) (need $( $key.Value ))" -status "FAIL"
            }
        }
        else
        {
            errorMsg -msg "FAIL ($( $key.Value ) required, current state - not defined)`n"
            bindReportArray -arrType "regPolicy" -Name $key.GPO_Name -state "not defined (need $( $key.Value ))" -status "FAIL"
            # TODO: FIXING
        }
    }
}

# Networks
# -------------------------------------------------------\

# Disable IPv6 and File and Printer sharings for Microsoft Networks
function disableSharing
{

    if ($isAdmin)
    {
        if ($autofix)
        {
            Disable-NetAdapterBinding -InterfaceAlias "Ethernet" -ComponentID ms_server
        }
    }
    else
    {
        warningMsg -msg "For fix status use -autofix argument with elevated prompt`n"
    }

}

function enableSharing
{
    Enable-NetAdapterBinding -InterfaceAlias "Ethernet" -ComponentID ms_server
}

function checkFileSharingStatus
{
    $status = Get-NetAdapterBinding | ? { $_.DisplayName -eq 'File and Printer Sharing for Microsoft Networks' -and $_.Name -eq 'ethernet' } | Select Enabled

    regularMsg -msg "File and Printer sharing status "

    foreach ($feature in $features.features_list)
    {
        if ($feature.Name -eq "File and Printer Sharing for Microsoft Networks")
        {

            if ($status.Enabled)
            {

                if ($feature.Status -eq "Disabled")
                {
                    errorMsg -msg "Current status Enabled (must be $( $feature.Status )) - FAIL`n"
                    if ($isAdmin)
                    {
                        if ($autofix)
                        {
                            disableSharing
                        }
                    }
                    else
                    {
                        warningMsg -msg "For fix status use -autofix argument with elevated prompt`n"
                    }
                    #
                    bindReportArray -arrType "base" -Name "File and Printer sharing status (must be $( $feature.Status ))" -state "Enabled" -status "FAIL"
                }
                if ($feature.Status -eq "Enabled")
                {
                    infoMsg -msg "Enabled - OK`n"
                    bindReportArray -arrType "base" -Name "File and Printer sharing status (must be $( $feature.Status ))" -state "Enabled" -status "OK"
                }

            }
            else
            {

                if ($feature.Status -eq "Disabled")
                {
                    infoMsg -msg "Current status Disabled (must be $( $feature.Status )) - OK`n"
                    #
                    bindReportArray -arrType "base" -Name "File and Printer sharing status (must be $( $feature.Status ))" -state "Disabled" -status "OK"
                }
                if ($feature.Status -eq "Enabled")
                {
                    if ($isAdmin)
                    {
                        if ($autofix)
                        {
                            enableSharing
                        }
                    }

                    bindReportArray -arrType "base" -Name "File and Printer sharing status (must be $( $feature.Status ))" -state "Disabled" -status "FAIL"
                }
            }
        }
    }

}

function disableIPv6
{

    if ($isAdmin)
    {
        if ($autofix)
        {
            Disable-NetAdapterBinding –InterfaceAlias “Ethernet” –ComponentID ms_tcpip6
        }
    }
    else
    {
        warningMsg -msg "For fix status use -autofix argument with elevated prompt`n"
    }
}

function checkIPv6Status
{
    $status_ipv6 = Get-NetAdapterBinding | ? { $_.ComponentID -eq 'ms_tcpip6' -and $_.Name -eq 'ethernet' } | Select Enabled

    regularMsg -msg "Internet Protocol Version 6 (TCP/IPv6) "

    if ($status_ipv6.Enabled)
    {
        errorMsg -msg "Enabled - FAIL`n"

        if ($isAdmin)
        {
            if ($autofix)
            {
                disableIPv6
            }
        }
        else
        {
            warningMsg -msg "For fix status use -autofix argument with elevated prompt`n"
        }
        #
        bindReportArray -arrType "base" -Name "Internet Protocol Version 6 (TCP/IPv6)" -state "Enabled" -status "FAIL"
    }
    else
    {
        infoMsg -msg "Disabled - OK`n"
        #
        bindReportArray -arrType "base" -Name "Internet Protocol Version 6 (TCP/IPv6)" -state "Disabled" -status "OK"
    }
}

# # # End Processing

# Final
# -------------------------------------------------------------------------------------------\

function finalSteps
{

    $logData = Get-Content -Path $log

    # Write-Output $logData

    # Global errors counter
    if ($countError -gt 0)
    {
        $line; regularMsg -msg "Error counts "
        errorMsg -msg "$countError errors found`n"
        # Write-Error "test" -ErrorAction Stop
    }

    if (!$isAdmin)
    {
        $line; regularMsg -msg "Notice: "
        infoMsg -msg "Script run with not elevated prompt`n"
    }

    if ($autofix)
    {
        $line; regularMsg -msg "Notice: "
        warningMsg -msg "After autofix option, please restart computer and re-run script again`n"
    }

    if ($isExtra) {
        $line; regularMsg -msg "Extra functionality is enabled`n"
        runExtra
    }

    $line; regularMsg -msg "Notice: "
    infoMsg -msg "Read help .\$( $scriptName ) -help `n"
}

# Invoke section
# -------------------------------------------------------------------------------------------\

# writeLog -msg "Start script $timeStamp" -Severity Information
checkOSVersion
getOSWorksTime
statusDomainMemeber
getLocalUsers
$line
getDiskInfo
$line
checkPassPols
$line
checkAuditPolicy
$line
if (!$debug)
{ 
    checkRegPols
    $line   
    checkFeatures
    $line
    checkOldUpdates
    $line
    checkSVCs -services_type "restricted_services"
    $line
    checkSVCs -services_type "required_services"
    # checkServices
    $line
    checkSoftware
    $line
}
disableSharing
# disableIPv6
checkFileSharingStatus
checkIPv6Status
disableSMB1
disableSMB2_3
checkSMB1; checkSMB2
if (!$debug)
{
    checkWindowsTime
    #TODO: Add next step - Checking states
    $line
    checkPorts
    $line
}
checkUAC
checkPowerShellPolicy
###

# Global finality
# -------------------------------------------------------------------------------------------\

# Count errors, send log
finalSteps

# HTML
$mainSnippet = @"
<div class="header">
<h1>Security report. $hostName</h1>
<hr>
<ul>
    <li>Computer name - <b>$hostName</b></li>
    <li>OS - <b>$osName</b>
        <ul>
            <li>Last boot time - <b>$osBootTime</b></li>
            <li>Has been up for - <b>$osWorksTime</b></li>
            <li>Installation date - <b>$osInstallDate</b></li>
            <li>Build number - <b>$osBuild</b></li>
            <li>Architecture - <b>$osArch</b></li>
            <li>Product ID - <b>$osSerial</b></li>
            <li>Product Key - <b>$osKey</b></li>
            <li>UUID - <b>$osUUID</b></li>
        </ul>
    </li>
    <li>User - <b>$currentUser (elevated - $isAdmin)</b></li>
    <li>Internal IP - <b>$internalIP</b></li>
    <li>Founded Errors / Warnings - <b id="errorTag">$countError</b></li>
</ul>
</div>
<hr>
<div class="main">
"@

$scriptSnippet = @"
</div>
<footer><i>Report created - <b>$timeStamp</b></i></footer>
<script type="text/javascript">
  var tds = document.getElementsByTagName('td');
  for (var i = 0; i < tds.length; i++) {
    if (tds[i].innerHTML.indexOf("FAIL") !== -1) {
      console.log('The ' + tds[i].textContent + ' is endangered!');
      tds[i].style.color = "#d85c5c";
      tds[i].style.fontWeight = "900";
    }
    if (tds[i].innerHTML.indexOf("OK") !== -1) {
      tds[i].style.color = "#4aa74a";
      tds[i].style.fontWeight = "900";
    }
    if (tds[i].innerHTML.indexOf("WARNING") !== -1) {
      tds[i].style.color = "#fd772d";
      tds[i].style.fontWeight = "900";
    }
    if (tds[i].innerHTML.indexOf("INFO") !== -1) {
      tds[i].style.color = "#003366";
    }
  var element = document.getElementById('errorTag');
  element.style.fontWeight = "900";
  if (element.innerHTML.indexOf("0") !== -1) {
      element.style.color = "#d85c5c";
    }
    else {
        element.style.color = "#d85c5c";
    }
  }
</script>
"@

$html += $mainSnippet

$html += $localUsers | Select Name, Disabled, LockOut, 'Password Expires', 'Password Last Set', 'Last logon' | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Local Users Information</h2>"
$html += $diskInfo | Select Name, 'Total(GB)', 'Free(GB)', 'Free(%)' | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Disk info (sorted by free space percentage)</h2>"
$html += $localPasswordPolicy | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Password policy info</h2>"
$html += $localAuditPolicy | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Audit policy info</h2>"
$html += $localRegistryPolicy | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Security Options policy info</h2>"
$html += $reportBaseSettings | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Base security settings</h2>"
$html += $reportFeatures | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Installed Windows features</h2>"
$html += $reportRequiredServices | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Requred services status</h2>"
$html += $reportRestrictedServices | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Restricted services status</h2>"
$html += $reportPorts | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Listening ports</h2>"
$html += $reportSoft | Select Name, State, Status | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Software</h2>"

$html += $scriptSnippet

function createReport
{
    param (
        [Parameter(Mandatory = $true)]$title,
        [Parameter(Mandatory = $true)]$data
    )

    ConvertTo-Html -head $Head -Title $title -Body $data | Out-File $htmlReport
}

function createJSON
{
    param(
        [Parameter(Mandatory = $true)]$fileName,
        [Parameter(Mandatory = $true)]$data,
        [Parameter(Mandatory = $true)]$apiLink
    )

    $header = @{"X-CWiCCS"="Hello world!"}
    $header += @{"X-CWiCCS-TOKEN"=$config.App_Token}
    $body = $data | ConvertTo-Json

    $path = $jsonFolder + "\" + $fileName
    $data | ConvertTo-Json | Set-Content -Path $path

    # TODO - create folder for computer and collect json to jsonFolder
    # Invoke-WebRequest "http://192.168.10.19:8000/test-post"  -Body $body -Method 'POST' -Headers $header

    if (checkHttpStatus -url $config.App_Web_Server)
    {
        $uri = $config.App_Web_Server + $apiLink
        Invoke-RestMethod -Method post -ContentType 'Application/Json' -Headers $header -Body $body -Uri $uri
    }
    else
    {
        Write-Host "Web serer is down!"
    }


}

createReport -title "Security report - $hostName" -data $html

if ($report)
{
    start $htmlReport
}

if ($json)
{
    createJSON -data $localUsers -fileName "localUsers.json" -apiLink "/test-post"

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


# getGPOProfile

# Temporary section
# ----------------
# start $htmlReport
# Write-Host $reportSoft.Count
