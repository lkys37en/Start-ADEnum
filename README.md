# Start-ADEnum
A tool to automate Active Directory enumeration.

Special thanks to 
* Sean Metcalf [@pyrotek3](https://twitter.com/pyrotek3) 
* Will Schroeder [@harmj0y](https://twitter.com/harmj0y),
* Dirk-jan [@_dirkjan](https://twitter.com/_dirkjan),
* Rohan Vazarkar [@cptjesus](https://twitter.com/cptjesus),
* Matt Graeber [@mattifestation](https://twitter.com/mattifestation),
* Vincent Le Toux [@mysmartlogon](https://twitter.com/mysmartlogon),
* Mike Loss [@mikeloss](https://twitter.com/mikeloss)

For their hard work in Active Directory research and tool creation.

## Tool Prereq

This tool requires that you have a runas /netonly shell.

## Functions  
* [Start-PreReqCheck](#Start-Prereqcheck)
* [Install-Tools](#Install-Tools)
* [Start-ADEnum](#Start-ADEnum)

## Start-PreReqCheck 
This function determines if the current Windows 10 OS is 1809+ and installs all the prerequisites. The list of prerequisites includes the following:

* Identifies if current Windows 10 host is on version 1809+ and installs RSAT tools via Feature on Demand. 

* Determines if Powerview, Bloodhound, Grouper and PingCastle exist in the C:\tools\ directory. If not the script will invoke the Install-Tools script.

* Disables Defender real time monitoring to allow 3rd party modules to run.


## Install-Tools

This function is invoked from Start-PreReqCheck in the event the below modules aren't currently installed. Furthermore, chocolatey (https://chocolatey.org/) and git (https://chocolatey.org/packages/git) are installed to allow cloning of the GitHub repositories. 

* PowerView
* Bloodhound
* Grouper
* PingCastle

## Start-ADEnum  

This function performs the following actions:

* Performs individual scans on specific domains or on all domains automatically identified via trust enumeration.

* Creates PowerShell jobs for each domain and for each type of scan.

The following scans types are available:
* Powerview - Run various commands to dump a list of users, computers, local group membership, high value domain group membership, etc. Refer to https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon for a full list of commands.

* Bloodhound - Runs collection method All with the skipping option. Refer to to https://github.com/BloodHoundAD/BloodHound/wiki/Data-Collector for a full list of collector options.

* Grouper - Utilizes RSAT Get-GPOReport to extract a GPO Report in xml format that can then be parsed by Grouper to identify any vulnerable settings within Group Policy.

* Ping Castle - Perform an Active Directory health check and runs various scanners such as open share, SMB version and signing enabled, spooler service available, null sessions on hosts/trusts and laps/bitlocker checks.

## Paramters
* ClientName

    Enter the client name for folder structure.


* Path

    Enter path where evidence will be placed. If folder doesn't already exist, the script will create it.

* Domains

    Enter individual domain to enumerate or let the script automatically identify all vailable domains via trust enumeration.

* Scan

    Enter individual scan(s) to perform. Scans that are available include Active Directory Certificate Services (ADCS) , Bloodhound, GPOReport, PowerView, PingCastle, PrivExchange, and All

## Examples

Gathers a list of all domain/forest by enumerating trusts and runs all scans against each domain found.

    Start-ADEnum -ClientName lkylabs -Path C:\Projects -Scan All


Runs all scans against lkylabs.com and corp.lkylabs.com.

    Start-ADEnum -ClientName lkylabs -Path C:\Projects -Domains lkylabs.com  -Scan All
    

Runs PowerView and Bloodhound scans against lkylabs.com and corp.lkylabs.com domains.
    
    Start-ADEnum -ClientName lkylabs -Path C:\Projects -Domains lkylabs.com,corp.lkylabs.com  -Scan PowerView,Bloodhound
