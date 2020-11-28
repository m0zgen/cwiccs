New-Variable -Force -Name services -Option AllScope -Value @()
New-Variable -Force -Name software -Option AllScope -Value @()
New-Variable -Force -Name features -Option AllScope -Value @()
New-Variable -Force -Name ports -Option AllScope -Value @()
New-Variable -Force -Name gpo -Option AllScope -Value @()

# Configs / Whitelists / Profiles
function bindConfigs
{
    param(
        [Parameter(Mandatory = $true)]
        [string]$configName
    )

    # Write-Host "Bind profile - $($configName.ToUpper() )"
    regularMsg -msg "Bind profile "
    infoMsg -msg "$( $configName.ToUpper() )`n"

    # Configs / Whitelists / Profiles
    if (Test-Path -LiteralPath @($scriptFolder + "\config\profiles\$( $configName )\services.json"))
    {
        $services = Get-Content -Path @($scriptFolder + "\config\profiles\$( $configName )\services.json") | ConvertFrom-Json
    }
    else
    {
        Write-Host "Please put 'config' folder in to the script folder!"; Exit 1
    }
    if (Test-Path -LiteralPath @($scriptFolder + "\config\profiles\$( $configName )\software.json"))
    {
        $software = Get-Content -Path @($scriptFolder + "\config\profiles\$( $configName )\software.json") | ConvertFrom-Json
    }
    else
    {
        Write-Host "Please put 'config' folder in to the script folder!"; Exit 1
    }
    if (Test-Path -LiteralPath @($scriptFolder + "\config\profiles\$( $configName )\ports.json"))
    {
        $ports = Get-Content -Path @($scriptFolder + "\config\profiles\$( $configName )\ports.json") | ConvertFrom-Json
    }
    else
    {
        Write-Host "Please put 'config' folder in to the script folder!"; Exit 1
    }
    if (Test-Path -LiteralPath @($scriptFolder + "\config\profiles\$( $configName )\gpo.json"))
    {
        $gpo = Get-Content -Path @($scriptFolder + "\config\profiles\$( $configName )\gpo.json") | ConvertFrom-Json
    }
    else
    {
        Write-Host "Please put 'config' folder in to the script folder!"; Exit 1
    }
    if (Test-Path -LiteralPath @($scriptFolder + "\config\profiles\$( $configName )\features.json"))
    {
        $features = Get-Content -Path @($scriptFolder + "\config\profiles\$( $configName )\features.json") | ConvertFrom-Json
    }
    else
    {
        Write-Host "Please put 'config' folder in to the script folder!"; Exit 1
    }
}

if ($profile.Count -ne 0)
{
    Write-Host "Profile passed..."
    # Reads from -profile argument
    foreach ($p in $profile)
    {
        if (Test-Path -LiteralPath @($scriptFolder + "\config\profiles\" + $p))
        {
            bindConfigs -configName $p
        }
        else
        {
            Write-Host "Profile does not found!"
            Write-Host "You can view all available profiles with [-profilelist] argument"
            Exit 1
        }
    }
}
else
{
    bindConfigs -configName "default"
}