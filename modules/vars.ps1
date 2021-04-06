# VARS
# -------------------------------------------------------------------------------------------\
# $os = Get-WMIObject -class win32_operatingsystem
$os = Get-CimInstance -class Win32_OperatingSystem
# This method can be use - $os.Caption
$osName = $os.Name.Substring(0,$os.Name.IndexOf('|'))
$osBuild = $os.BuildNumber
$osArch = $os.OSArchitecture
$osSerial = $os.SerialNumber
$osInstallDate = $os.InstallDate
$osKey = $( Get-WindowsProductKey )
$osUUID = $( Get-OsUUID )
# $osInstallDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate)
$isAdmin = $( isAdministrator )
$hostName = $env:computername
$localhost = '.' # or you can determine localhost directly as 'localhost'
$currentUser = $env:USERNAME
$internalIP = $( getIP )
$countError = 0
$line = "-------------------------------------------------"
# Get services array
$timeStamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
$dateStamp = (Get-Date).toString("yyyy-MM-dd")
$logFolder = $scriptFolder + "\log"
$reportsFolder = $scriptFolder + "\reports"
$jsonFolder = $scriptFolder + "\reports\json"
$secPolExported = $( $Env:TEMP ) + "\security-policy.inf"

$global:isDomain = $( isDomainMember )
if ($isDomain)
{
    $global:domainName = ((gwmi Win32_ComputerSystem).Domain)
    $global:domainRole = $( detectDomainRole )
}

# Logs / Report folders
# -------------------------------------------------------------------------------------------\
createFolder $logFolder; createFolder $reportsFolder; createFolder $jsonFolder
$log = $logFolder + "\check-" + $dateStamp + ".log"

# HTML
# -------------------------------------------------------------------------------------------\
New-Variable -Force -Name htmlData -Option AllScope -Value @()
$htmlReport = $scriptFolder + "\reports\sec-report-" + $hostName + "-" + $dateStamp + ".html"

# Clear and bind html report vars
# -------------------------------------------------------------------------------------------\
Clear-Variable -Name ("count*", "os*", "html*", "report*", "local*", "online*", "json*", "*eId") -Scope Global
New-Variable -Force -Name countError -Option AllScope -Value 0
New-Variable -Force -Name osBootTime -Option AllScope -Value ""
New-Variable -Force -Name osWorksTime -Option AllScope -Value ""
New-Variable -Force -Name localUsers -Option AllScope -Value @()
New-Variable -Force -Name diskInfo -Option AllScope -Value @()
New-Variable -Force -Name localPasswordPolicy -Option AllScope -Value @()
New-Variable -Force -Name localAuditPolicy -Option AllScope -Value @()
New-Variable -Force -Name localRegistryPolicy -Option AllScope -Value @()

# HTML Report Array Fragments
New-Variable -Force -Name reportRestrictedServices -Option AllScope -Value @()
New-Variable -Force -Name reportRequiredServices -Option AllScope -Value @()
New-Variable -Force -Name reportPorts -Option AllScope -Value @()
New-Variable -Force -Name reportSoft -Option AllScope -Value @()
New-Variable -Force -Name reportDisks -Option AllScope -Value @()
New-Variable -Force -Name reportBaseSettings -Option AllScope -Value @()
New-Variable -Force -Name reportFeatures -Option AllScope -Value @()

# JSON Objects
New-Variable -Force -Name deviceId -Option AllScope -Value @()
New-Variable -Force -Name onlineId -Option AllScope
New-Variable -Force -Name entryId -Option AllScope
New-Variable -Force -Name jsonDisks -Option AllScope -Value @()
New-Variable -Force -Name jsonFeatures -Option AllScope -Value @()
New-Variable -Force -Name jsonLocalAuditPolicies -Option AllScope -Value @()
New-Variable -Force -Name jsonLocalPasswordPolicies -Option AllScope -Value @()
New-Variable -Force -Name jsonLocalRegistryPolicies -Option AllScope -Value @()
New-Variable -Force -Name jsonLocalUsers -Option AllScope -Value @()

#>
