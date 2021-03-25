
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

    try
    {
        [pscustomobject]@{
            Time = (Get-Date -f g)
            Message = $msg
            Severity = $Severity
        } | Export-Csv -Path "$log" -Append -NoTypeInformation
    }
    catch
    {
        Write-Host "Can't write log file - Permission denied"
    }

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

function debugMsg
{
    param
    ([Parameter(Mandatory = $true)]$msg)
    $line
    # -BackgroundColor white
    Write-Host $msg " - DEBUG`n"  -ForegroundColor Magenta -NoNewline; writeLog -msg "$msg" -Severity Warning
    $line
    [Console]::ResetColor()
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

    regularMsg -msg "PowerShell version "
    if ($psv -gt 5 -or $psv -eq 5 -and $psv -lt 8)
    {
        infoMsg -msg "v$( $psv )`n"
    }
    elseif ($psv -lt 5)
    {
        warningMsg -msg "Please upgrade your PowerShell version (minimal v5).`nCurrent version is $( $psv )
You can download WMF 5.1 from here - https://www.microsoft.com/en-us/download/details.aspx?id=54616"
        Exit 1
    }
    else
    {
        warningMsg -msg "This PowerShell version does not supported yet. Supported versions v5-v6.`nCurrent version is $( $psv )`n"
        Exit 1
    }

}

function clearSpace($val)
{
    $val = $val -replace '\s',''
    return $val
}

# Checks domain member status
# -------------------------------------------------------------------------------------------\
function isDomainMember
{
    if ((Get-CimInstance win32_computersystem).partofdomain -eq $true) {
        return $true;
    }
    return $false;
}

# DomainRole
# Data type: uint16
# Access type: Read-only

# Value Meaning
# 0 (0x0)  Standalone Workstation
# 1 (0x1)  Member Workstation
# 2 (0x2)  Standalone Server
# 3 (0x3)  Member Server
# 4 (0x4)  Backup Domain Controller
# 5 (0x5)  Primary Domain Controller

function detectDomainRole
{
    Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty DomainRole
}

$global:isDomain = $( isDomainMember )
if ($isDomain)
{
    $global:domainName = ((gwmi Win32_ComputerSystem).Domain)
    $global:domainRole = $( detectDomainRole )
}

# Get Windows Product Key
function Get-WindowsProductKey
{
  # test whether this is Windows 7 or older:
  function Test-Win7
  {
    $OSVersion = [System.Environment]::OSVersion.Version
    ($OSVersion.Major -eq 6 -and $OSVersion.Minor -lt 2) -or
    $OSVersion.Major -le 6
  }

  # implement decoder
  $code = @'
// original implementation: https://github.com/mrpeardotnet/WinProdKeyFinder
using System;
using System.Collections;

  public static class Decoder
  {
        public static string DecodeProductKeyWin7(byte[] digitalProductId)
        {
            const int keyStartIndex = 52;
            const int keyEndIndex = keyStartIndex + 15;
            var digits = new[]
            {
                'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'M', 'P', 'Q', 'R',
                'T', 'V', 'W', 'X', 'Y', '2', '3', '4', '6', '7', '8', '9',
            };
            const int decodeLength = 29;
            const int decodeStringLength = 15;
            var decodedChars = new char[decodeLength];
            var hexPid = new ArrayList();
            for (var i = keyStartIndex; i <= keyEndIndex; i++)
            {
                hexPid.Add(digitalProductId[i]);
            }
            for (var i = decodeLength - 1; i >= 0; i--)
            {
                // Every sixth char is a separator.
                if ((i + 1) % 6 == 0)
                {
                    decodedChars[i] = '-';
                }
                else
                {
                    // Do the actual decoding.
                    var digitMapIndex = 0;
                    for (var j = decodeStringLength - 1; j >= 0; j--)
                    {
                        var byteValue = (digitMapIndex << 8) | (byte)hexPid[j];
                        hexPid[j] = (byte)(byteValue / 24);
                        digitMapIndex = byteValue % 24;
                        decodedChars[i] = digits[digitMapIndex];
                    }
                }
            }
            return new string(decodedChars);
        }

        public static string DecodeProductKey(byte[] digitalProductId)
        {
            var key = String.Empty;
            const int keyOffset = 52;
            var isWin8 = (byte)((digitalProductId[66] / 6) & 1);
            digitalProductId[66] = (byte)((digitalProductId[66] & 0xf7) | (isWin8 & 2) * 4);

            const string digits = "BCDFGHJKMPQRTVWXY2346789";
            var last = 0;
            for (var i = 24; i >= 0; i--)
            {
                var current = 0;
                for (var j = 14; j >= 0; j--)
                {
                    current = current*256;
                    current = digitalProductId[j + keyOffset] + current;
                    digitalProductId[j + keyOffset] = (byte)(current/24);
                    current = current%24;
                    last = current;
                }
                key = digits[current] + key;
            }

            var keypart1 = key.Substring(1, last);
            var keypart2 = key.Substring(last + 1, key.Length - (last + 1));
            key = keypart1 + "N" + keypart2;

            for (var i = 5; i < key.Length; i += 6)
            {
                key = key.Insert(i, "-");
            }

            return key;
        }
   }
'@
  # compile c#:
  Add-Type -TypeDefinition $code
 
  # get raw product key:
  $digitalId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DigitalProductId).DigitalProductId
  
  $isWin7 = Test-Win7
  if ($isWin7)
  {
    # use static c# method:
    [Decoder]::DecodeProductKeyWin7($digitalId)
  }
  else
  {
    # use static c# method:
    [Decoder]::DecodeProductKey($digitalId)
  }
}

# Get UUID
function Get-OsUUID
{
    (Get-CimInstance -Class Win32_ComputerSystemProduct).UUID
}


# HTTP worker
# Accept Self Signed cert
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
{
    $certCallback = @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static void Ignore()
        {
            if(ServicePointManager.ServerCertificateValidationCallback ==null)
            {
                ServicePointManager.ServerCertificateValidationCallback +=
                    delegate
                    (
                        Object obj,
                        X509Certificate certificate,
                        X509Chain chain,
                        SslPolicyErrors errors
                    )
                    {
                        return true;
                    };
            }
        }
    }
"@
    Add-Type $certCallback
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
[ServerCertificateValidationCallback]::Ignore()

function checkHttpStatus
{
    param (
        [Parameter(Mandatory = $true)]$url
    )
    try {
        Write-host "Verifying $url" -ForegroundColor Yellow

        $checkConnection = Invoke-WebRequest -Uri $url
        if ($checkConnection.StatusCode -eq 200) {
            Write-Host "Connection Verified!" -ForegroundColor Green
            return 1
        }

    }
    catch [System.Net.WebException] {
        $exceptionMessage = $Error[0].Exception
        if ($exceptionMessage -match "503") {
            Write-Host "Server Unavaiable" -ForegroundColor Red
        }
        elseif ($exceptionMessage -match "404") {
            Write-Host "Page Not found" -ForegroundColor Red
        }
        return 0
    }
}
 #>
