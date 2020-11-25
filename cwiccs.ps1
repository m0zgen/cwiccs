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

$scriptFolder = $( getScriptDirPath ); cd $scriptFolder

# Initial functions / messages / warnings / etc
. .\modules\common.ps1

. .\modules\bind-arrays.ps1
. .\modules\initial-html.ps1

. .\modules\os.ps1
. .\modules\localusers.ps1
. .\modules\checkPorts.ps1
. .\modules\getInstalledSoftware.ps1
. .\modules\reg-handler.ps1
. .\modules\uac.ps1
. .\modules\svc-handler.ps1
. .\modules\ntp.ps1

. .\modules\features.ps1

# VARS
# -------------------------------------------------------------------------------------------\

$scriptName = $MyInvocation.MyCommand.Name
$os = Get-WMIObject -class win32_operatingsystem
$osName = $os.Name.Substring(0,$os.Name.IndexOf('|'))
$osInstallDate = $os.ConvertToDateTime($os.InstallDate)
$isAdmin = $( isAdministrator )
$hostName = $env:computername
$currentUser = $env:USERNAME
$internalIP = $( getIP )
$countError = 0
$line = "-------------------------------------------------"
# Get services array
$timeStamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
$dateStamp = (Get-Date).toString("yyyy-MM-dd")
$logFolder = $scriptFolder + "\log"
$reportsFolder = $scriptFolder + "\reports"
$secPolExported = $( $Env:TEMP ) + "\security-policy.inf"
# Create log folder
createFolder $logFolder; createFolder $reportsFolder
$log = $logFolder + "\check-" + $dateStamp + ".log"

# HTML
New-Variable -Force -Name htmlData -Option AllScope -Value @()
$htmlReport = $scriptFolder + "\reports\sec-report-" + $hostName + "-" + $dateStamp + ".html"


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
. .\modules\bind-profiles.ps1

# Common / Service Functions
# -------------------------------------------------------------------------------------------\

if ($help)
{   
    . .\modules\help.ps1
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
        secedit.exe /export /cfg $p
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

}

#if ($admin -or $elevate)
#{
#    Start-Process -FilePath PowerShell -ArgumentList "-ExecutionPolicy Bypass -Command & {$ScriptBlock exportGPO -p $secPolExported}" -verb RunAs
#}
if ($isAdmin)
{
    secedit.exe /export /cfg $secPolExported
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
    bindReportArray -arrType "auditPolicy" -Name "Need elevated" -state "0" -status "WARNING"
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
            bindReportArray -arrType "passwordPolicy" -Name $policy -state $splitted -status "INFO"

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
                            } else {
                                errorMsg -msg "$splitted - must be $( $gpoparam.State ) FAIL`n"
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
    Disable-NetAdapterBinding -InterfaceAlias "Ethernet" -ComponentID ms_tcpip6
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
getLocalUsers
$line
checkPassPols
$line
checkRegPols
$line
if (!$debug)
{    
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
}
checkPorts
$line
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
            <li>OS last boot time - <b>$osBootTime</b></li>
            <li>OS has been up for - <b>$osWorksTime</b></li>
            <li>Installation date - <b>$osInstallDate</b></li>
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
      element.style.color = "#4aa74a";

    }
    else {
        element.style.color = "#d85c5c";
    }
  }
</script>
"@

$html += $mainSnippet

$html += $localUsers | Select Name, Disabled, LockOut, 'Password Expires', 'Password Last Set', 'Last logon' | ConvertTo-Html -Fragment -As Table -PreContent "<h2>Local Users Information</h2>"
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

createReport -title "Security report - $hostName" -data $html

if ($report)
{
    start $htmlReport
}


# getGPOProfile

# Temporary section
# ----------------
# start $htmlReport
# Write-Host $reportSoft.Count
