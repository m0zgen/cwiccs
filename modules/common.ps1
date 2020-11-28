# Clear and bind html report vars
Clear-Variable -Name ("count*", "html*", "report*", "local*") -Scope Global
New-Variable -Force -Name countError -Option AllScope -Value 0
New-Variable -Force -Name osBootTime -Option AllScope -Value ""
New-Variable -Force -Name osWorksTime -Option AllScope -Value ""
New-Variable -Force -Name localUsers -Option AllScope -Value @()
New-Variable -Force -Name localPasswordPolicy -Option AllScope -Value @()
New-Variable -Force -Name localAuditPolicy -Option AllScope -Value @()
New-Variable -Force -Name localRegistryPolicy -Option AllScope -Value @()

# HTML Report Array Fragments
New-Variable -Force -Name reportRestrictedServices -Option AllScope -Value @()
New-Variable -Force -Name reportRequiredServices -Option AllScope -Value @()
New-Variable -Force -Name reportPorts -Option AllScope -Value @()
New-Variable -Force -Name reportSoft -Option AllScope -Value @()
New-Variable -Force -Name reportBaseSettings -Option AllScope -Value @()
New-Variable -Force -Name reportFeatures -Option AllScope -Value @()

# Get local IP server address
function getIP
{
    $ipAddress = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.status -ne "Disconnected" }).IPv4Address.IPAddress
    return $ipAddress
}

# Check is current user / session run as elevated prompt - true / false
function isAdministrator
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Generate folder

function createFolder($path)
{
    If(!(test-path $path))
    {
          New-Item -ItemType Directory -Force -Path $path > $null
    }
}

# function createFolder($path)
# {
#     $foldPath = $null
#     foreach ($foldername in $path.split("\"))
#     {
#         $foldPath += ($foldername + "\")
#         if (!(Test-Path $foldPath))
#         {
#             New-Item -ItemType Directory -Path $path > $null
#             Write-Host "$global:foldPath Folder Created Successfully"
#             Write-Host "$path Folder Created Successfully"
#         }
#     }
# }

# Logging / Messaging
# -------------------------------------------------------------------------------------------\

# Logger
function writeLog
{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$msg,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Severity = 'Error'
    )

    [pscustomobject]@{
        Time = (Get-Date -f g)
        Message = $msg
        Severity = $Severity
    } | Export-Csv -Path "$log" -Append -NoTypeInformation
}

# Messages
function errorMsg
{
    param
    ([Parameter(Mandatory = $true)]$msg)
    Write-Host - $msg -ForegroundColor Red -NoNewline; $countError++; writeLog -msg "$msg" -Severity Error
}
function infoMsg
{
    param
    ([Parameter(Mandatory = $true)]$msg)
    Write-Host - $msg -ForegroundColor Green -NoNewline;
}
function warningMsg
{
    param
    ([Parameter(Mandatory = $true)]$msg)
    Write-Host $msg  -ForegroundColor Yellow -NoNewline; writeLog -msg "$msg" -Severity Warning
}
function regularMsg
{
    param
    ([Parameter(Mandatory = $true)]$msg)
    Write-Host $msg -ForegroundColor White -NoNewline;
}
function noticeMsg
{
    param
    ([Parameter(Mandatory = $true)]$msg)
    Write-Host - $msg -ForegroundColor Magenta -NoNewline;
}

# common Messages
function cmAutofixNote
{
    if (!$autofix)
    {
        warningMsg -msg " (-autofix will resolve this problem)`n"
    }
    else
    {
        regularMsg -msg "`n"
    }
}

# Send error to System Windows event log
function sendErrorToEvtx
{
    param
    (
        [Parameter(Mandatory = $true)]$service,
        [Parameter(Mandatory = $true)]$errorMessage
    )
    eventcreate /Id 500 /D "$service - $errorMessage" /T ERROR /L system
}

function checkPowerShellVersion
{
    
    $psv = $PSVersionTable.PSVersion.Major

    if ($psv -gt 5 -or $psv -eq 5 -and $psv -lt 8)
    {
        infoMsg -msg "PowerShell version is $( $psv )..."
    }
    elseif ($psv -lt 5)
    {
        warningMsg -msg "Please upgrade your PowerShell version (minimal v5).`nCurrent version is $( $psv )"
    }
    else
    {
        warningMsg -msg "This PowerShell version does not supported yet. Supported versions v5-v6.`nCurrent version is $( $psv )"
        Exit 1
    }

}

