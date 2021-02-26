
# Collect installed software info
# -------------------------------------------------------------------------------------------\

function getInstalledSoftware
{
    [OutputType('System.Software.Inventory')]
    [Cmdletbinding()]

    Param(
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String[]]$Computername = $env:COMPUTERNAME)

    Process {
        $Paths = @("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "SOFTWARE\\Wow6432node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")

        ForEach ($Path in $Paths)
        {
            Write-Verbose  "Checking Path: $Path"
            #  Create an instance of the Registry Object and open the HKLM base key
            Try
            {
                $reg = [microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine', $Computer, 'Registry64')
            }
            Catch
            {
                Write-Error $_
                Continue
            }

            #  Uninstall get each children
            Try
            {
                $regkey = $reg.OpenSubKey($Path)
                # get subkey names
                $subkeys = $regkey.GetSubKeyNames()

                ForEach ($key in $subkeys)
                {
                    Write-Verbose "Key: $Key"
                    $thisKey = $Path + "\\" + $key

                    Try
                    {
                        $thisSubKey = $reg.OpenSubKey($thisKey)
                        # Prevent Objects with empty DisplayName
                        $DisplayName = $thisSubKey.getValue("DisplayName")

                        If ($DisplayName -AND $DisplayName -notmatch '^Update  for|rollup|^Security Update|^Service Pack|^HotFix')
                        {

                            $Date = $thisSubKey.GetValue('InstallDate')
                            If ($Date)
                            {
                                Try
                                {
                                    $Date = [datetime]::ParseExact($Date, 'yyyyMMdd', $Null)
                                }
                                Catch
                                {
                                    Write-Warning "$( $Computer ): $_ <$( $Date )>"
                                    $Date = $Null
                                }
                            }

                            $Publisher = Try
                            {
                                $thisSubKey.GetValue('Publisher').Trim()
                            }
                            Catch
                            {
                                $thisSubKey.GetValue('Publisher')
                            }

                            $Version = Try
                            {
                                $thisSubKey.GetValue('DisplayVersion').TrimEnd(([char[]](32, 0)))
                            }
                            Catch
                            {
                                $thisSubKey.GetValue('DisplayVersion')
                            }

                            $UninstallString = Try
                            {
                                $thisSubKey.GetValue('UninstallString').Trim()
                            }
                            Catch
                            {
                                $thisSubKey.GetValue('UninstallString')
                            }

                            $InstallLocation = Try
                            {
                                $thisSubKey.GetValue('InstallLocation').Trim()
                            }
                            Catch
                            {
                                $thisSubKey.GetValue('InstallLocation')
                            }

                            $InstallSource = Try
                            {
                                $thisSubKey.GetValue('InstallSource').Trim()
                            }
                            Catch
                            {
                                $thisSubKey.GetValue('InstallSource')
                            }

                            $HelpLink = Try
                            {
                                $thisSubKey.GetValue('HelpLink').Trim()
                            }
                            Catch
                            {
                                $thisSubKey.GetValue('HelpLink')
                            }

                            $Object = [pscustomobject]@{
                                Computername = $Computer
                                DisplayName = $DisplayName
                                Version = $Version
                                InstallDate = $Date
                                Publisher = $Publisher
                                UninstallString = $UninstallString
                                InstallLocation = $InstallLocation
                                InstallSource = $InstallSource
                                HelpLink = $thisSubKey.GetValue('HelpLink')
                                EstimatedSizeMB = [decimal]([math]::Round(($thisSubKey.GetValue('EstimatedSize') * 1024) / 1MB, 2))
                            }
                            $Object.pstypenames.insert(0, 'System.Software.Inventory')
                            # Write-Output $Object
                            # return $Object
                            new-object psobject -property  @{ Name = $Object.DisplayName; Version = $Object.Version }
                        }
                    }
                    Catch
                    {
                        Write-Warning "$Key : $_"
                    }
                }
            }
            Catch
            {
            }
            $reg.Close()
        }
    }
}

# Checking Software
# -------------------------------------------------------------------------------------------\

# Checking requre software and requre installed software version
function checkSoftware()
{

    $countReqSoft = 0
    $countFoundSoft = 0
    $realInstalledReqSoftwareNames = @()

    $installedSoftware = getInstalledSoftware | ToArray

    ForEach ($package in $installedSoftware)
    {
        ForEach ($required in $software.required_software)
        {

            $countReqSoft++
            if ($package.Name.ToLower() -Match $required.Name.ToLower())
            {
                $countFoundSoft++
                regularMsg -msg "$( $package.Name ) "
                infoMsg -msg "Found - OK "

                if ($package.Version -ge $required.Version)
                {
                    infoMsg "Version - OK`n"
                    #

                    bindReportArray -arrType "soft" -Name "$( $package.Name ) - actual version " -state "$( $package.Version )" -status "OK"
                }
                else
                {
                    errorMsg "Oldest Version - FAIL`n"
                    writeLog -msg "$package.Name is outdated. Current version is $package.Version, required version $required.Version" -Severity Error
                    #
                    bindReportArray -arrType "soft" -Name "$( $package.Name ) - Oldest version " -state "$( $package.Version )" -status "FAIL"
                }

                $realInstalledReqSoftwareNames += $package.Name
            }
        }
    }
    if ($countReqSoft -ne $countFoundSoft)
    {
        $countError++
    }

    # IF SOFTWARE DOES NOT FOUND. FIX EMPTY ARRAY ERROR
    $tmpInstalled = @()

    if ($installedSoftware.Count -gt 0)
    {
        if ($installedSoftware.Count -eq 1)
        {
            $tmpInstalled += ""
        }
        ForEach ($t in $installedSoftware)
        {
            $tmpInstalled += ,$t.Name
        }

        [System.Collections.ArrayList]$installedArray = $tmpInstalled
        $installedArray = $installedArray | Sort-Object -Unique
    }
    else
    {
        regularMsg -msg "Installed software "
        warningMsg -msg "Does not found`n"
    }

    if ($realInstalledReqSoftwareNames.Count -gt 0)
    {
        if ($realInstalledReqSoftwareNames.Count -eq 1)
        {
            $realInstalledReqSoftwareNames += ""
        }
        [System.Collections.ArrayList]$realArray = $realInstalledReqSoftwareNames
        $realArray = $realArray | Sort-Object -Unique
    }
    else
    {
        regularMsg -msg "Requirement software "
        warningMsg -msg "Does not found`n"
    }

    #
    if ($realInstalledReqSoftwareNames.Count -gt 0 -And $installedSoftware.Count -gt 0)
    {
        $ss = Compare-Object -ReferenceObject $installedArray -DifferenceObject $realArray

        foreach ($s in $ss)
        {

            # write-host $s

            if ($s.SideIndicator -eq "<=")
            {
                regularMsg -msg "$( $s.InputObject ) "
                warningMsg -msg "Unknown software - WARNING`n"
                #
                bindReportArray -arrType "soft" -Name "$( $s.InputObject )" -state "Not defined" -status "WARNING"
            }
        }
    }
    else
    {
        if ($installedSoftware.Count -gt 0)
        {
            foreach ($item in $installedSoftware)
            {
                regularMsg -msg "$( $item.Name ) "
                warningMsg -msg "Found unknown software - WARNING`n"
                bindReportArray -arrType "soft" -Name "$( $item.Name )" -state "Not defined" -status "WARNING"
            }
        }
    }
}