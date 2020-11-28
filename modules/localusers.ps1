# Collect Users Information
function getLocalUsers
{
    $now = Get-Date
    $AllLocalAccounts = Get-CimInstance -Class Win32_UserAccount -Filter "LocalAccount='$True'"
    # $AllLocalAccounts = Get-CimInstance -Class Win32_UserAccount -Namespace "root\cimv2" ` -Filter "LocalAccount='$True'"

    $localUsers = $AllLocalAccounts | ForEach-Object {
        $user = ([adsi]"WinNT://$computer/$( $_.Name ),user")
        $pwAge = $user.PasswordAge.Value
        $maxPwAge = $user.MaxPasswordAge.Value
        $pwLastSet = $now.AddSeconds(-$pwAge)
        $lastChangePwd = (net user $_.Name | findstr /B /C:"Password last set").trim("Password last set")
        $lastlogonstring = (net user $_.Name | findstr /B /C:"Last logon").trim("Last logon")

        New-Object -TypeName PSObject -Property @{
            'Name' = $_.Name
            'Full Name' = $_.FullName
            'Disabled' = $_.Disabled
            'Status' = $_.Status
            'LockOut' = $_.LockOut
            'Password Expires' = $_.PasswordExpires
            'Password Required' = $_.PasswordRequired
            'Account Type' = $_.AccountType
            'Domain' = $_.Domain
            'Last logon' = $lastlogonstring
            'Password Last Set' = $lastChangePwd
            'Password Age' = ($now - $pwLastSet).Days
            'Password Expiry Date' = $now.AddSeconds($maxPwAge - $pwAge)
            'Description' = $_.Description
        }
    }

    $line; regularMsg "Local users info...`n"
    foreach ($user in $localUsers)
    {
        $user.Las

        regularMsg -msg "$( $user.Name )"
        infoMsg -msg "Disabled - $( $user.Disabled ), Last Logon - $( $user.'Last logon' ), Pwd exp - $( $user.'Password Expires' ), Pwd last set $( $user.'Password Last Set' )`n"
    }
}