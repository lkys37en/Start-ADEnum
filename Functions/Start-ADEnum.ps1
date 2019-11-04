Function Start-ADEnum {
    <#
    .SYNOPSIS
    Author: @lkys37en
    Required Dependencies: Powershell Version 5.x, Windows 10 1803 or 1809
    Optional Dependencies: None

    .DESCRIPTION
    This tool is used to automate Active Directory enumeration. The tool requires a domain context via runas /only. All tool dependencies will be installed during first run.

    .PARAMETER ClientName
    Enter clientname for folder structure.

    .PARAMETER Path
    Enter path where evidence will be placed. If folder doesn't already exist, the script will create it.

    .PARAMETER Domain
    Enter individual domain to enumerate or let the script automatically identify all vailable domains via trust enumeration.

    .PARAMETER Scan
    Enter individual scan(s) to perform.

    .EXAMPLE
    PS C:\> Start-ADEnum  -ClientName lkylabs -Path C:\Projects -Scan All
    Collects a list of all domain/forest trusts and runs all scans against each domain found.

    .EXAMPLE
    PS C:\> Start-ADEnum  -ClientName lkylabs -Path C:\Projects -Domain lkylabs.com  -Scan All
    Runs all scans against lkylabs.com.

    .EXAMPLE
    PS C:\> Start-ADEnum  -ClientName lkylabs -Path C:\Projects -Domain lkylabs.com,corp.lkylabs.com  -Scan PowerView,Bloodhound,
    Runs PowerView and Bloodhound scans against lkylabs.com and corp.lkylabs.com domains.

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ClientName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $false)]
        [String[]]
        $Domain,

        [Parameter(Mandatory = $True)]
        [ValidateSet("ADCS", "Bloodhound", "GPOReport", "PowerView", "PingCastle", "PrivExchange", "All")]
        [String[]]
        $Scan
    )

    Begin {
        #Folders variable
        $Folders = @(
            "PingCastle"
            "PowerView"
            "Bloodhound"
            "GPO" 
            "Microsoft Services\Exchange"
            "Microsoft Services\ADCS"
        )

        #Installs all prereqs if missing
        Write-Host -ForegroundColor Green "[*] Performing prereqs check"
        Start-PrereqCheck

        Import-Module C:\Tools\PowerSploit\Recon\PowerView.ps1

        #Checking Domain Context before moving forward
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() | Out-Null
        }

        catch {
            throw "[*] Not currently assoicated with a domain account, perform runas /netonly before enumerating AD $($_.Exception.Message)"
        }
        
        #Creating Path and evidence folder structure
        if ((Test-Path $Path) -eq $false) {
            try {
                Write-Host -ForegroundColor Green "[+] Creating $Path Folder "
                mkdir -Path $Path | Out-Null
            }

            catch {
                throw "An error has occurred $($_.Exception.Message)"
            }


            try {
                Write-Host -ForegroundColor Green "[+] Creating $ClientName Folder"
                mkdir -Path $Path\$ClientName | Out-Null
            }

            catch {
                throw "An error has occurred  $($_.Exception.Message)"
            }

            try {
                if ($Domain) {
                    $Domains = $Domain
                }

                else {
                    Write-Host -ForegroundColor "[*] Collecting a list of domains.."
                    $Domains = (Get-DomainTrustMapping -API).TargetName | Select-Object -Unique
                    if ($Domains -eq $null) { $Domains = (Get-NetDomain).Name }
                }

                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Magenta "[*] Creating $Domain evidence folders"
                    mkdir -Path "$Path\$ClientName\$Domain" | Out-Null

                    foreach ($folder in $folders) {
                        mkdir -Path "$Path\$ClientName\$Domain\$folder" | Out-Null
                    }
                }
            }

            catch {
                throw "An error has occurred  $($_.Exception.Message)"
            }
        }

        elseif ((Test-Path $Path) -eq $true) {
            try {
                if ((Test-Path $Path\$ClientName) -eq $false ) {
                    Write-Host -ForegroundColor Green "[+] Creating $ClientName Folder"
                    mkdir -Path $Path\$ClientName | Out-Null
                }
            }

            catch {
                throw "An error has occurred  $($_.Exception.Message)"
            }
        
            #Set domain variable to determine if single or multiple domains need to be tested
            try {
                if ($Domain) {
                    $Domains = $Domain
                }

                else {
                    Write-Host -ForegroundColor Green "[*] Collecting a list of domains.."
                    $Domains = (Get-DomainTrustMapping -API).TargetName | Select-Object -Unique
                    if ($Domains -eq $null) { $Domains = (Get-NetDomain).Name }
                }

                foreach ($Domain in $Domains) {
                    if ((Test-Path -Path $Path\$ClientName\$Domain) -eq $false) {
                        Write-Host -ForegroundColor Magenta "[*] Creating $Domain evidence folders"
                        mkdir -Path "$Path\$ClientName\$Domain" | Out-Null
                    }
                    foreach ($folder in $folders) {
                        if ((Test-Path "$Path\$ClientName\$Domain\$folder") -eq $false) {
                            mkdir -Path "$Path\$ClientName\$Domain\$folder" | Out-Null
                        }
                    }
                }
            }
        
            catch {
                throw "An error has occurred  $($_.Exception.Message)"
            }
        }
    }

    Process {
        #Running PowerView commands
        $PowerViewScriptBlock = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\PowerView\"

            #Encryption type array used in converting number values in users/computer msDS-SupportedEncryptionTypes attribute
            $EncryptionTypes = @{
                "1"  = "DES_CRC"                
                "2"  = "DES_MD5"
                "3"  = "DES_CRC,DES_MD5"
                "4"  = "RC4"
                "8"  = "AES128"
                "16" = "AES256"
                "24" = "AES128,AES256"
                "28" = "RC4,AES128,AES256"
                "31" = "DES_CRC,DES_MD5,RC4,AES128,AES256"
            }

            #Importing needed modules
            Import-Module "C:\Tools\PowerSploit\Recon\PowerView.ps1"

            #Dump domain policy
            (Get-DomainPolicy -Domain $Domain).SystemAccess | Out-File ($Folder, $Domain + "_" + "Domain_Password_Policy.txt" -join "")

            #Dump forest functional level
            Get-NetForest | Out-File ($Folder, $Domain + "_" + "Forest_Functional_Level.txt" -join "")

            #Dump domain function level
            Get-NetDomain | Out-File ($Folder, $Domain + "_" + "Domain_Functional_Level.txt" -join "")

            #Krbtgt Password Last Set
            Get-NetUser -Identity krbtgt | Out-File ($Folder, $Domain + "_" + "Krbtgt_Account.txt" -join "")

            #Gather a list of Domain Controllers
            Get-NetDomainController -Domain $Domain | Select-Object -Property Forest, Domain, Name, SiteName, IPAddress | Export-CSV ($Folder, $Domain + "_" + "DomainControllers.csv" -join "") -NoTypeInformation

            #Dump AD Sites
            Get-DomainSite -Domain $Domain | Select-Object -Property name, siteobject, whencreated, whenchanged | Export-CSV ($Folder, $Domain + "_" + "ADSites.csv" -join "") -NoTypeInformation

            #AD SiteSubnets
            Get-DomainSubnet -Domain $Domain | Select-Object -Property name, siteobject, whencreated, whenchanged | Export-CSV ($Folder, $Domain + "_" + "ADSubnets.csv" -join "") -NoTypeInformation

            #Dump DNS Records
            Get-DomainDNSRecord -Domain $Domain -ZoneName $Domain | Select-Object -Property zonename, name, Data, recordtype, distinguishedname, whencreated, whenchanged | Export-CSV ($Folder, $Domain + "_" + "DNSRecords.csv" -join "") -NoTypeInformation

            #Get a list of shares
            Get-DomainFileServer -Domain $Domain | Out-File ($Folder, $Domain + "_" + "Fileservers.txt" -join "")

            #Get a list of DFS Shares
            Get-DomainDFSShare -Domain $Domain | Export-CSV ($Folder, $Domain + "_" + "DFSShares.csv" -join "") -NoTypeInformation

            #Dump a list of OU's
            Get-DomainOU -Domain $Domain | Select-Object -Property name, description, distinguishedname, whencreated, objectguid, gplink | Export-CSV ($Folder, $Domain + "_" + "OU.csv" -join "") -NoTypeInformation

            #Dumping all SPN's in hashcat format
            Get-DomainUser -SPN -Domain $Domain | Get-DomainSPNTicket -OutputFormat hashcat | Export-CSV ($Folder, $Domain + "_" + "SPNs.csv" -join "") -NoTypeInformation

            #Dumping all AD user objects
            $Users = Get-DomainUser * -Domain $Domain

            foreach ($User in $Users) {
                $UserProperties = [ordered] @{
                    'name'                                     = $User.name;
                    'samaccountname'                           = $User.samaccountname;
                    'userprincipalname'                        = $User.userprincipalname;
                    'mail'                                     = $User.mail;
                    'displayname'                              = $User.displayname;
                    'description'                              = $User.description;
                    'department'                               = $User.department;
                    'objectSid'                                = $User.objectSid;
                    'sIDHistory'                               = $User.sIDHistory;
                    'memberof'                                 = $User.memberof;
                    'whencreated'                              = $User.whencreated;
                    'pwdlastset'                               = $User.pwdlastset;
                    'lastlogontimestamp'                       = $User.lastlogontimestamp;
                    'accountexpires'                           = $User.accountexpires;
                    'admincount'                               = $User.admincount;
                    'useraccountcontrol'                       = $User.useraccountcontrol;
                    'msDS-SupportedEncryptionTypes'            = if ($User.'msds-supportedencryptiontypes' -ne '') { $EncryptionTypes[($User.'msds-supportedencryptiontypes').ToString()] };
                    'serviceprincipalname'                     = if ($User.serviceprincipalname -ne '') { (($User.serviceprincipalname) -join ',') };
                    'msDS-AllowedToDelegateTo'                 = if ($User.'msDS-AllowedToDelegateTo' -ne '') { (($User.'msDS-AllowedToDelegateTo') -join ',') };
                    'msds-allowedtoactonbehalfofotheridentity' = if ($User.'msds-allowedtoactonbehalfofotheridentity' -ne '') { (New-Object Security.AccessControl.RawSecurityDescriptor($User.'msds-allowedtoactonbehalfofotheridentity', 0)).DiscretionaryAcl.SecurityIdentifier.Value | ConvertFrom-SID -Domain $Domain };
                }

                $object = New-Object -TypeName PSObject -Property $UserProperties
                $object | Export-Csv ($Folder, $Domain + "_" + "Users.csv" -join "") -NoTypeInformation -Append
            }

            #Dumping list of AD Groups
            Get-NetGroup -Identity * | Select-Object -Property samaccountname, description, objectsid, grouptype | Export-CSV ($Folder, $Domain + "_" + "Groups.csv" -join "") -NoTypeInformation

            #Dumping a list of foreign users
            Get-DomainForeignUser -Domain $Domain | Export-CSV ($Folder, $Domain + "_" + "ForeignUsers.csv" -join "") -NoTypeInformation

            #Dumping all AD computer objects
            $Computers = Get-DomainComputer * -Domain $Domain

            foreach ($Computer in $Computers) {
                $ComputerProperties = [ordered]@{
                    'Name'                                     = $Computer.name;
                    'UserName'                                 = $Computer.samaccountname
                    'IPv4Address'                              = ($Computer.dnshostname | Get-IPAddress).IPAddress
                    'DNSHostname'                              = $Computer.dnshostname;
                    'Operating System'                         = $Computer.operatingsystem;
                    'OS Version'                               = $Computer.operatingsystemversion;
                    'Description'                              = $Computer.description;
                    'ObjectSid'                                = $Computer.objectSid;
                    'SIDHistory'                               = $Computer.sIDHistory;
                    'Memberof'                                 = $Computer.memberof;
                    'Whencreated'                              = $Computer.whencreated;
                    'lastlogontimestamp'                       = $Computer.lastlogontimestamp;
                    'useraccountcontrol'                       = $Computer.useraccountcontrol;
                    'ms-mcs-admpwd'                            = $Computer.'ms-mcs-admpwd';
                    'ms-mcs-admpwdexpirationtime'              = [datetime]::FromFileTime([System.Convert]::ToInt64($Computer.'ms-mcs-admpwdexpirationtime'));
                    'msDS-SupportedEncryptionTypes'            = if ($Computer.'msds-supportedencryptiontypes' -ne '') { $EncryptionTypes[($Computer.'msds-supportedencryptiontypes').ToString()] };
                    'mS-DS-CreatorSID'                         = if ($Computer.'ms-ds-creatorsid' -ne '') { (New-Object System.Security.Principal.SecurityIdentifier($Computer.'ms-ds-creatorsid', 0)).Value | ConvertFrom-SID -Domain $Domain };
                    'msDS-AllowedToDelegateTo'                 = if ($Computer.'msDS-AllowedToDelegateTo' -ne '') { (($Computer.'msDS-AllowedToDelegateTo') -join ',') };
                    'msds-allowedtoactonbehalfofotheridentity' = if ($Computer.'msds-allowedtoactonbehalfofotheridentity' -ne '') { (New-Object Security.AccessControl.RawSecurityDescriptor($Computer.'msds-allowedtoactonbehalfofotheridentity', 0)).DiscretionaryAcl.SecurityIdentifier.Value | ConvertFrom-SID -Domain $Domain };
                }

                $object = New-Object -TypeName PSObject -Property $ComputerProperties
                $object | Export-CSV ($Folder, $Domain + "_" + "Computers.csv" -join "") -NoTypeInformation -Append
            }

            #Gathering users from local groups
            Find-DomainLocalGroupMember -ComputerDomain $Domain | Export-CSV ($Folder, $Domain + "_" + "LocalAdmins.csv" -join "") -NoTypeInformation
            Find-DomainLocalGroupMember -ComputerDomain $Domain -GroupName "Remote Desktop Users" | Export-CSV ($Folder, $Domain + "_" + "RDP_Users.csv" -join "") -NoTypeInformation
            Find-DomainLocalGroupMember -ComputerDomain $Domain -GroupName "Remote Management Users" | Export-CSV ($Folder, $Domain + "_" + "Winrm_Users.csv" -join "") -NoTypeInformation

            #Gathering members of specific domain groups
            $Groups = @(
                "Domain Admins"
                "Enterprise Admins"
                "Administrators"
                "Account Operators"
                "Backup Operators"
                "Cert Publishers"
                "DnsAdmins"
                "Hyper-V Administrators"
            )

            foreach ($Group in $Groups) {
                Get-NetGroupMember $Group -Domain $Domain -Recurse | Export-CSV ($Folder, $Domain + "_" + "$Group.csv" -join "") -NoTypeInformation
            }

            #Dump Trust details specifically looking for TGT delegation settings
            $Server = Get-ADDomainController -DomainName $Domain -Discover -NextClosestSite
            Get-ADTrust -Filter * -Server $Server.IPv4Address | Out-File ($Folder, $Domain + "_" + "Trusts.txt" -join "")
        }

        #Running Bloodhound commands
        $BloodhoundScriptBlock = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]

            #Importing needed modules
            Import-Module "C:\Tools\BloodHound\Ingestors\SharpHound.ps1"
            Import-Module "C:\Tools\PowerSploit\Recon\PowerView.ps1"

            $Folder = "$Path\$ClientName\$Domain\Bloodhound"
            Set-Location $Folder ; Invoke-Bloodhound -Domain $Domain -CollectionMethod All -SkipPing -ZipFileName ($Domain + "_" + "Bloodhound.zip")
        }

        #Running RSAT GPO Get-GPOReport commands
        $GPOReportScriptBlock = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\GPO\"

            #Importing needed modules
            Import-Module "C:\Tools\Grouper\grouper.psm1"
            Import-Module "C:\Tools\PowerSploit\Recon\PowerView.ps1"

            Get-GPOReport -All -ReportType xml -Domain $Domain -Path ($Folder, $Domain + "_" + "GPOReport.xml" -join "")
            Get-GPOReport -All -ReportType Html -Domain $Domain -Path ($Folder, $Domain + "_" + "GPOReport.html" -join "")
            Invoke-AuditGPOReport -Path ($Folder, $Domain + "_" + "GPOReport.xml" -join "") -Level 3 | Out-File ($Folder, $Domain + "_" + "GrouperResults.txt" -join "")
        }

        #Checking domain for Exchange PrivExchange vulnerability
        $PrivExchangeCheck = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\Microsoft Services\Exchange\"

            <#Reference:https://eightwone.com/references/schema-versions/
            https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/#>
            $ExchangeVersions = @{
                "15.02.0397.003" = "Exchange Server 2019 CU2, Not Vulnerable"
                "15.02.0330.005" = "Exchange Server 2019 CU1, Not Vulnerable"
                "15.02.0221.012" = "Exchange Server 2019 RTM, Vulnerable to PrivExchange!"
                "15.02.0196.000" = "Exchange Server 2019 Preview, Vulnerable to PrivExchange!"
                "15.01.1779.002" = "Exchange Server 2016 CU13, Not Vulnerable"
                "15.01.1713.005" = "Exchange Server 2016 CU12, Vulnerable to PrivExchange!"
                "15.01.1591.010" = "Exchange Server 2016 CU11, Vulnerable to PrivExchange!"
                "15.01.1531.003" = "Exchange Server 2016 CU10, Vulnerable to PrivExchange!"
                "15.01.1466.003" = "Exchange Server 2016 CU9, Vulnerable to PrivExchange!"
                "15.01.1415.002" = "Exchange Server 2016 CU8, Vulnerable to PrivExchange!"
                "15.01.1261.035" = "Exchange Server 2016 CU7, Vulnerable to PrivExchange!"
                "15.01.1034.026" = "Exchange Server 2016 CU6, Vulnerable to PrivExchange!"
                "15.01.0845.034" = "Exchange Server 2016 CU5, Vulnerable to PrivExchange!"
                "15.01.0669.032" = "Exchange Server 2016 CU4, Vulnerable to PrivExchange!"
                "15.01.0544.027" = "Exchange Server 2016 CU3, Vulnerable to PrivExchange!"
                "15.01.0466.034" = "Exchange Server 2016 CU2, Vulnerable to PrivExchange!"
                "15.01.0396.030" = "Exchange Server 2016 CU1, Vulnerable to PrivExchange!"
                "15.01.0225.042" = "Exchange Server 2016 RTM, Vulnerable to PrivExchange!"
                "15.01.0225.016" = "Exchange Server 2016 Preview, Vulnerable to PrivExchange!"
                "15.00.1497.002" = "Exchange Server 2013 CU23, Not Vulnerable"
                "15.00.1473.003" = "Exchange Server 2013 CU22, Not Vulnerable!"
                "15.00.1395.004" = "Exchange Server 2013 CU21, Vulnerable to PrivExchange!"
                "15.00.1367.003" = "Exchange Server 2013 CU20, Vulnerable to PrivExchange!"
                "15.00.1365.001" = "Exchange Server 2013 CU19, Vulnerable to PrivExchange!"
                "15.00.1347.002" = "Exchange Server 2013 CU18, Vulnerable to PrivExchange!"
                "15.00.1320.004" = "Exchange Server 2013 CU17, Vulnerable to PrivExchange!"
                "15.00.1293.002" = "Exchange Server 2013 CU16, Vulnerable to PrivExchange!"
                "15.00.1263.005" = "Exchange Server 2013 CU15, Vulnerable to PrivExchange!"
                "15.00.1236.003" = "Exchange Server 2013 CU14, Vulnerable to PrivExchange!"
                "15.00.1210.003" = "Exchange Server 2013 CU13, Vulnerable to PrivExchange!"
                "15.00.1178.004" = "Exchange Server 2013 CU12, Vulnerable to PrivExchange!"
                "15.00.1156.006" = "Exchange Server 2013 CU11, Vulnerable to PrivExchange!"
                "15.00.1130.007" = "Exchange Server 2013 CU10, Vulnerable to PrivExchange!"
                "15.00.1104.005" = "Exchange Server 2013 CU9, Vulnerable to PrivExchange!"
                "15.00.1076.009" = "Exchange Server 2013 CU8, Vulnerable to PrivExchange!"
                "15.00.1044.025" = "Exchange Server 2013 CU7, Vulnerable to PrivExchange!"
                "15.00.0995.029" = "Exchange Server 2013 CU6, Vulnerable to PrivExchange!"
                "15.00.0913.022" = "Exchange Server 2013 CU5, Vulnerable to PrivExchange!"
                "15.00.0847.032" = "Exchange Server 2013 SP1, Vulnerable to PrivExchange!"
                "15.00.0775.038" = "Exchange Server 2013 CU3, Vulnerable to PrivExchange!"
                "15.00.0712.024" = "Exchange Server 2013 CU2, Vulnerable to PrivExchange!"
                "15.00.0620.029" = "Exchange Server 2013 CU1, Vulnerable to PrivExchange!"
                "15.00.0516.032" = "Exchange Server 2013 RTM, Vulnerable to PrivExchange!"
            }
            $RootDSE = "DC=$($Domain.Replace('.', ',DC='))"
            $CN = (([ADSI]"LDAP://cn=Microsoft Exchange,cn=Services,cn=Configuration,$RootDSE")).Children
            $ExchangeVersion = ($CN).msExchProductID
            $ExchangeVersions[$ExchangeVersion] | Out-File ($Folder, $Domain + "_" + "ExchangeVersion.txt" -join "")
        }

        #Command to extract Active Directory Certificate Services usable certificates
        $ADCS = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\Microsoft Services\ADCS\"

            #Identify instances of Active Directory Certificate Service
            $RootDSE = "DC=$($Domain.Replace('.', ',DC='))"
            $CAs = ([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$RootDSE").Children

            #Dumping list of available certificates
            foreach ($CA in $CAs) {
                Write-Host -ForegroundColor Green "[+] Extracting a list of available certificates for $($CA.displayName)"
                $CA.certificateTemplates | Out-File ($Folder, $Domain + "_" + $CA.displayName + "_" + "available_certs.txt" -join "")
            }
        }

        #Running PingCastle commands
        $PingCastleScriptBlock = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\PingCastle\"

            #PingCastle scanner commands
            $Arguments = @(
                "--server $Domain --healthcheck --no-enum-limit"
                "--scanner laps_bitlocker --server $Domain"
                "--scanner nullsession --server $Domain"
                "--scanner nullsession-trust --server $Domain"
                "--scanner share --server $Domain"
                "--scanner smb --server $Domain"
                "--scanner spooler --server $Domain"
                "--scanner startup --server $Domain"
            )

            #Running all scanner commands
            foreach ($Argument in $Arguments) {
                Set-Location $Folder ; Start-Process C:\tools\PingCastle\PingCastle.exe -ArgumentList $Argument -Wait
            }

            $Output = (Get-ChildItem $Folder -Exclude *html*, *xml*).FullName

            #Converting PingCastle text files into CSV's
            foreach ($Item in $Output) {
                Import-Csv -Path $Item -Delimiter "`t" | Export-Csv -Path  ($Folder + ($Item -split "\\" -replace "ad_scanner_" -replace ".txt" | Select-Object -Skip 5) + ".csv" -join "") -NoTypeInformation
            }

            #Remove original text files
            (Get-ChildItem $Folder).FullName | Remove-Item -Include *.txt
        }

        switch ($Scan) {
            "All" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting All AD Enum for $Domain"
                    Start-Job -ScriptBlock $PowerViewScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name PowerView_$Domain | Out-Null
                    Start-Job -ScriptBlock $PingCastleScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name PingCastle_$Domain | Out-Null
                    Start-Job -ScriptBlock $BloodhoundScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name BloodHound_$Domain | Out-Null
                    Start-Job -ScriptBlock $GPOReportScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name GPOReport_$Domain | Out-Null
                    Start-Job -ScriptBlock $PrivExchangeCheck -ArgumentList $ClientName, $Path, $Domain -Name PrivExchange_$Domain | Out-Null
                    Start-Job -ScriptBlock $ADCS -ArgumentList $ClientName, $Path, $Domain -Name ADCS_$Domain | Out-Null
                }
            }

            "ADCS" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting AD Certificate Services Enum for $Domain"
                    Start-Job -ScriptBlock $ADCS -ArgumentList $ClientName, $Path, $Domain -Name PrivExchange_$Domain | Out-Null
                }
            }

            "PowerView" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting PowerView Enum for $Domain"
                    Start-Job -ScriptBlock $PowerViewScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name PowerView_$Domain | Out-Null
                }
            }

            "PingCastle" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting Ping Castle AD Enum for $Domain"
                    Start-Job -ScriptBlock $PingCastleScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name PingCastle_$Domain | Out-Null
                }
            }

            "Bloodhound" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting Bloodhound AD Enum for $Domain"
                    Start-Job -ScriptBlock $BloodhoundScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name BloodHound_$Domain | Out-Null
                }
            }

            "GPOReport" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting GPO Report AD Enum for $Domain"
                    Start-Job -ScriptBlock $GPOReportScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name GPOReport_$Domain | Out-Null
                }
            }

            "PrivExchange" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting PrivExchange AD Enum for $Domain"
                    Start-Job -ScriptBlock $PrivExchangeCheck -ArgumentList $ClientName, $Path, $Domain -Name PrivExchange_$Domain | Out-Null
                }
            }
        }
    }
}