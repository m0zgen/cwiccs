## Check Windows and Control Configs and Security

[![made-with-powershell](https://img.shields.io/badge/PowerShell-1f425f?logo=Powershell)](https://microsoft.com/PowerShell)
[![Windows Latest](https://github.com/m0zgen/cwiccs/actions/workflows/windows-latest.yml/badge.svg)](https://github.com/m0zgen/cwiccs/actions/workflows/windows-latest.yml)
[![Windows 2019](https://github.com/m0zgen/cwiccs/actions/workflows/windows-2019.yml/badge.svg)](https://github.com/m0zgen/cwiccs/actions/workflows/windows-2019.yml)
[![Windows 2016](https://github.com/m0zgen/cwiccs/actions/workflows/windows-2016.yml/badge.svg)](https://github.com/m0zgen/cwiccs/actions/workflows/windows-2016.yml)


CWiCCS (read as QUICKS) - Checking and Controlling and Fixing some Windows settings from defined / whitelisted system config profiles

![cwiccs.org](./docs/images/logo.png)

---

* Compatibility list
  * Windows Server 2012/2016/2019
  * Windows 10 (tested on Windows Pro)
  * Powershell v5, v6, v7

* Enabled Feature Lists
* Local Group Policy settings
  * Password Policy
    * Max password age
    * Min password age
    * Minimum password length
    * Password history
    * Lockout threshold
    * Lockout duration
  * Audit Policy
  * Security Options
* Port listing
* System Services
* Installed Software List

Also CWiCCS checks:
* NTP (Windows Time)
* SMB
* Network options
  * File Sharing status
  * IPv6 status
  * Current internal IP
* UAC
* PowerShell execution policies
* Windows Update status
* Users list
  * Name
  * Enabled/Disabled status
  * LockOut
  * Password Expires
  * Password Last Set
  * Last Logon
* OS info
  * Windows Version
  * Last boot time
  * How long OS is Up
* Found errors counting

CWiCCS can generate:

* HTML reports
* Working status logs

## Support Platforms

CWiCCS tested on native Windows PowerShell on the:
* Windows 2012R2
* Windows 2016
* Windows 2019

On the PowerShell versions v5, v6

## Download / Install

You can clone repository:

```
git clone https://github.com/m0zgen/cwiccs.git
```

or

You can download archive from repository - Code > Download as ZIP

## Runs / Options

After download CWiCCS, please `cd` to `cwiccs` folder and them run script:

```powershell
.\cwiccs.ps1
```

Run with bypass powershell execution policy:

```powershell
powershell.exe -ep Bypass .\cwiccs.ps1 -report
```

### Unblock files

Unlock files:
```powershell
Get-ChildItem <cwiccs-master folder path> -recurse | Unblock-File
```

### Use in GPO

Command:
```powershell
c:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Script parameters:
```powershell
-ExecutionPolicy Bypass <path to shared folder>\cwiccs.ps1
```

### How to Self Sign
```powershell
Get-ChildItem -Path C:\Share\cwiccs-master\*.ps1 -Recurse | Set-AuthenticodeSignature -Certificate (Get-ChildItem -Path Cert:\CurrentUser\My\ -CodeSigningCert)
```

Additional info:
* https://sys-adm.in/programming/powershell-menu/882-powershell-kak-sozdat-sertifikat-i-podpisat-skript.html

### Use PSExec

You can use PSExec utility:

```powershell
PsExec.exe -s -i @c:\Share\servers.txt -e cmd /c "powershell -ExecutionPolicy Bypass \\dc01\Share\cwiccs-master\cwiccs.ps1"
```
or:

```powershell
PsExec.exe -s -i @c:\Share\servers.txt Powershell -File \\dc01\Share\cwiccs-master\cwiccs.ps1
```

Available options:
```
- cwiccs.ps1 [-autofix] [-report] [-elevate] [-admin] [-profile] <profilename> [-profilelist] [-help]
- [-elevate] and [-admin] arguments it is same (made for convenience)
```

## Operating Modes

CWiCCS can works with two modes:

1. from simple user
2. from elevated (Administrator) mode

`-autofix` option can works only from elevated mode

## Profiles

You can define own profile. CWiCCS use as default DEFAUL profile. Defined profiles:

* Features
* Gpo
* Ports
* Services
* Software

## Contribing

You can send me feature requests to [forum.sys-adm.in](https://forum.sys-adm.in/) with new topic which contains `#cwiccs` tag

## Info

* Russian Article - [CWiCCS (Check Windows and Control Configs and Security) - PowerShell инструмент для проверки и контроля Windows конфигураций](https://sys-adm.in/systadm/windows/933-cwiccs-check-windows-and-control-configs-and-security-powershell-instrument-dlya-proverki-i-kontrolya-windows-konfiguratsij.html)
