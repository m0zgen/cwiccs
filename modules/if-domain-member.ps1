function isDomainMember
{
    if ((gwmi win32_computersystem).partofdomain -eq $true) {
        return 1
    } else {
        return 0
    }
}

function statusDomainMemeber
{
    write-host "Computer status "
    if (isDomainMember) {
        write-host "Domain member`n"
    } else {
        write-host "Workgroup member`n"
    }
}

statusDomainMemeber