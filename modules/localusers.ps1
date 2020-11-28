# Collect Users Information
function getLocalUsers
{
    
    $line; regularMsg "Local users info...`n"
        
    if ($domainRole -eq 5) {
        warningMsg -msg "This is PDC (PDC - does not has local users info)`n"

        $localUsers = New-Object -TypeName PSObject -Property @{
            'Name' = 'Primary'
            'Disabled' = 'Domain'
            'LockOut' = 'Controller'
            'Password Expires' = 'Does not'
            'Password Last Set' = 'Has'
            'Last logon' = 'Local Users'
        }

    }
    else {
        
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

        foreach ($user in $localUsers)
        {
            $user.Las

            regularMsg -msg "$( $user.Name )"
            infoMsg -msg "Disabled - $( $user.Disabled ), Last Logon - $( $user.'Last logon' ), Pwd exp - $( $user.'Password Expires' ), Pwd last set $( $user.'Password Last Set' )`n"
        }
        
    }
    

}