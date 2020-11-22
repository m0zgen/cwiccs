## Check Windows and Control Configs and Security

CWiCCS (read as QUICKS) - Checking and Controlling and Fixing some Windows settings from defined / whitelisted system config profiles:

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

## Operating Modes

CWiCCS can works with two modes:

1. from simple user
2. from elevated (Administrator) mode

`-autofix` option can works only from elevated mode

## Options

Available options:
```
- cwiccs.ps1 [-autofix] [-report] [-elevate] [-admin] [-profile] <profilename> [-profilelist] [-help]
- [-elevate] and [-admin] arguments it is same (made for convenience)
```

## Profiles

You can define own profile. CWiCCS use as default DEFAUL profile. Defined profiles:

* Features
* Gpo
* Ports
* Services
* Software

## Contribing

You can send me feature requests to [forum.sys-adm.in](https://forum.sys-adm.in/) with new topic which contains `#cwiccs` tag

