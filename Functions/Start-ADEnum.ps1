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

    .PARAMETER Domains
    Enter individual domains to enumerate or let the script automatically identify all vailable domains via trust enumeration.

    .PARAMETER Scan
    Enter individual scan(s) to perform.

    .EXAMPLE
    PS C:\> Start-ADEnum  -ClientName lkylabs -Path C:\Projects -Scan All
    Collects a list of all domain/forest trusts and runs all scans against each domain found.

    .EXAMPLE
    PS C:\> Start-ADEnum  -ClientName lkylabs -Path C:\Projects -Domain lkylabs.com  -Scan All
    Runs all scans against a single domain.

    .EXAMPLE
    PS C:\> Start-ADEnum  -ClientName lkylabs -Path C:\Projects -Domain lkylabs.com,corp.lkylabs.com  -Scan PowerView,Bloodhound,
    Runs PowerView and Bloodhound scans against domains lkylabs.com and corp.lkylabs.com.

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ClientName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $False)]
        [String[]]
        $Domains,

        [Parameter(Mandatory = $True)]
        [ValidateSet("ADCS", "Bloodhound", "GPOReport", "PowerView", "PingCastle", "PowerUPSQL", "PrivExchange", "All", "QuickScan")]
        [String[]]
        $Scan,

        [Parameter(Mandatory = $False)]
        [String]
        $UserName
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
            "PowerUPSQL"
            "QuickScan"
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
                if (!($Domains)) {
                    Write-Host -ForegroundColor Green "[*] Collecting a list of domains.."
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
                if (!($Domains)) {
                    Write-Host -ForegroundColor Green "[*] Collecting a list of domains.."
                    $Domains = (Get-DomainTrustMapping -API).TargetName | Select-Object -Unique
                    if ($Domains -eq $null) { $Domains = (Get-NetDomain).Name }
                }

                foreach ($Domain in $Domains) {
                    if ((Test-Path $Path\$ClientName\$Domain) -eq $false) {
                    Write-Host -ForegroundColor Magenta "[*] Creating $Domain evidence folders"
                    mkdir -Path "$Path\$ClientName\$Domain" | Out-Null
                    }

                    foreach ($folder in $folders) {
                        if ((Test-Path $Path\$ClientName\$Domain\$folder) -eq $false) {
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

            #Identifying nearest domain controller
            $DC = (Get-NetDomain -Domain $Domain).PdcRoleOwner.Name

            #Domain Policy
            (Get-DomainPolicy -Domain $Domain -Server $DC).SystemAccess | Out-File ($Folder, $Domain + "_" + "Domain_Password_Policy.txt" -join "")

            #Forest Functional Level
            Get-NetForest | Out-File ($Folder, $Domain + "_" + "Forest_Functional_Level.txt" -join "")

            #Domain Function Level
            Get-NetDomain | Out-File ($Folder, $Domain + "_" + "Domain_Functional_Level.txt" -join "")

            #Krbtgt Password Last Set
            Get-NetUser -Identity krbtgt -Server $DC | Out-File ($Folder, $Domain + "_" + "Krbtgt_Account.txt" -join "")

            #Gather a list of Domain Controllers
            Get-NetDomainController -Domain $Domain -Server $DC | Select-Object -Property Forest, Domain, Name, SiteName, IPAddress | Export-CSV ($Folder, $Domain + "_" + "DomainControllers.csv" -join "") -NoTypeInformation

            #AD Sites
            Get-DomainSite -Domain $Domain -Server $DC | Select-Object -Property name, siteobject, whencreated, whenchanged | Export-CSV ($Folder, $Domain + "_" + "ADSites.csv" -join "") -NoTypeInformation

            #AD SiteSubnets
            Get-DomainSubnet -Domain $Domain -Server $DC | Select-Object -Property name, siteobject, whencreated, whenchanged | Export-CSV ($Folder, $Domain + "_" + "ADSubnets.csv" -join "") -NoTypeInformation

            #Dump DNS Records
            $DNSZones = (Get-DomainDNSZone -Domain $Domain -Server $DC).Name
            foreach ($Zone in $DNSZones) {
                Get-DomainDNSRecord -Domain $Domain -ZoneName $Domain -Server $DC | Select-Object -Property zonename, name, Data, recordtype, distinguishedname, whencreated, whenchanged | Export-CSV ($Folder, $Domain + "_" + "DNSRecords.csv" -join "") -NoTypeInformation
            }

            #Get a list of OU's
            Get-DomainOU -Domain $Domain -Server $DC | Select-Object -Property name, description, distinguishedname, whencreated, objectguid, gplink | Export-CSV ($Folder, $Domain + "_" + "OU.csv" -join "") -NoTypeInformation

            #Dumping all SPN's in hashcat format and gathering members of specific domain groups
            $SPNS = Get-DomainUser -SPN -Domain $Domain -Server $DC | Get-DomainSPNTicket -OutputFormat hashcat

            $Groups = @(
                "Domain Admins"
                "Enterprise Admins"
                "Administrators"
            )

            foreach ($Group in $Groups) {
                Get-NetGroupMember -Identity $Group -Domain $Domain -Server $DC -Recurse -OutVariable SensitiveUser | Export-CSV ($Folder, $Domain + "_" + "$Group.csv" -join "") -NoTypeInformation
            }

            foreach ($SPN in $SPNS) {
                $UserProperties = [ordered] @{
                    'SamAccountName'                           = $SPN.samaccountname;
                    'ServicePrincipalName'                     = (($SPN.serviceprincipalname) -join ',');
                    # Determine if user is a member of AD sensitive groups
                    'SensitiveUser'                             = if ($SPN.samaccountname | Where-Object {$SensitiveUser.MemberName -like $_}) {Write-Output "Yes"} ;
                    'Hash'                                     = ($SPN.Hash)
                }

                $object = New-Object -TypeName PSObject -Property $UserProperties
                $object | Export-CSV ($Folder, $Domain + "_" + "SPNs.csv" -join "") -NoTypeInformation -Append
            }

#            #Gathering members of specific domain groups
#            $Groups = @(
#                "Domain Admins"
#                "Enterprise Admins"
#                "Administrators"
#                "Account Operators"
#                "Backup Operators"
#                "Cert Publishers"
#                "DnsAdmins"
#                "Hyper-V Administrators"
#            )
#            foreach ($Group in $Groups) {
#                Get-NetGroupMember -Identity $Group -Domain $Domain -Server $DC -Recurse | Export-CSV ($Folder, $Domain + "_" + "$Group.csv" -join "") -NoTypeInformation
#            }

            #Dump Trust details specifically looking for TGT delegation settings
            Get-ADTrust -Filter * -Server $DC.Value | Out-File ($Folder, $Domain + "_" + "Trusts.txt" -join "") -NoTypeInformation

            #Dumping all AD user objects
            $Users = Get-DomainUser * -Domain $Domain -Server $DC

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
                    'msDS-SupportedEncryptionTypes'            = if ($User.'msds-supportedencryptiontypes') { $EncryptionTypes[($User.'msds-supportedencryptiontypes').ToString()] };
                    'serviceprincipalname'                     = (($User.serviceprincipalname) -join ',');
                    'msDS-AllowedToDelegateTo'                 = (($User.'msDS-AllowedToDelegateTo') -join ',');
                    'msds-allowedtoactonbehalfofotheridentity' = if ($User.'msds-allowedtoactonbehalfofotheridentity') { (New-Object Security.AccessControl.RawSecurityDescriptor($User.'msds-allowedtoactonbehalfofotheridentity', 0)).DiscretionaryAcl.SecurityIdentifier.Value | ConvertFrom-SID -Domain $Domain };
                }

                $object = New-Object -TypeName PSObject -Property $UserProperties
                $object | Export-Csv ($Folder, $Domain + "_" + "Users.csv" -join "") -NoTypeInformation -Append
            }

            #Dumping all AD computer objects
            $Computers = Get-DomainComputer * -Domain $Domain -Server $DC

            foreach ($Computer in $Computers) {
                $ComputerProperties = [ordered]@{
                    'Name'                                     = $Computer.name;
                    'UserName'                                 = $Computer.samaccountname
                    'Enabled'                                  = (Get-ADComputer -Identity $Computer.Name -Server $DC).Enabled;
                    'IPv4Address'                              = (Get-ADComputer -Identity $Computer.Name -Properties IPv4Address -Server $DC).IPv4Address;
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
                    'msDS-SupportedEncryptionTypes'            = if ($Computer.'msds-supportedencryptiontypes') { $EncryptionTypes[($Computer.'msds-supportedencryptiontypes').ToString()] };
                    'mS-DS-CreatorSID'                         = if ($Computer.'ms-ds-creatorsid') { (New-Object System.Security.Principal.SecurityIdentifier($Computer.'ms-ds-creatorsid', 0)).Value | ConvertFrom-SID -Domain $Domain };
                    'ms-mcs-admpwd'                            = $Computer.'ms-mcs-admpwd';
                    'ms-mcs-admpwdexpirationtime'              = [datetime]::FromFileTime([System.Convert]::ToInt64($Computer.'ms-mcs-admpwdexpirationtime'))
                    'msDS-AllowedToDelegateTo'                 = (($Computer.'msDS-AllowedToDelegateTo') -join ',');
                    'msds-allowedtoactonbehalfofotheridentity' = if ($Computer.'msds-allowedtoactonbehalfofotheridentity') { (New-Object Security.AccessControl.RawSecurityDescriptor($Computer.'msds-allowedtoactonbehalfofotheridentity', 0)).DiscretionaryAcl.SecurityIdentifier.Value | ConvertFrom-SID -Domain $Domain };
                }

                $object = New-Object -TypeName PSObject -Property $ComputerProperties
                $object | Export-CSV ($Folder, $Domain + "_" + "Computers.csv" -join "") -NoTypeInformation -Append
            }

            #Gather a list of foreign users
            Get-DomainForeignUser -Domain $Domain -Server $DC | Export-CSV ($Folder, $Domain + "_" + "ForeignUsers.csv" -join "") -NoTypeInformation

            #Gathering users from local groups
            Find-DomainLocalGroupMember -ComputerDomain $Domain -GroupName "Remote Desktop Users" -Server $DC | Export-CSV ($Folder, $Domain + "_" + "RDP_Users.csv" -join "") -NoTypeInformation
            Find-DomainLocalGroupMember -ComputerDomain $Domain -GroupName "Remote Management Users" -Server $DC | Export-CSV ($Folder, $Domain + "_" + "Winrm_Users.csv" -join "") -NoTypeInformation
        }

        #Running Bloodhound commands
        $BloodhoundScriptBlock = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\Bloodhound"

            #Importing needed modules
            Import-Module "C:\Tools\PowerSploit\Recon\PowerView.ps1"

            $DC = (Get-NetDomain -Domain $Domain).PdcRoleOwner.Name

            Start-Process C:\Tools\BloodHound\Collectors\SharpHound.exe -Wait -ArgumentList "-d $Domain -c All --domaincontroller $DC --outputdirectory $Folder"
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

            $DC = (Get-NetDomain -Domain $Domain).PdcRoleOwner.Name
            Get-GPOReport -All -ReportType xml -Domain $Domain -Server $DC -Path ($Folder, $Domain + "_" + "GPOReport.xml" -join "")
            Get-GPOReport -All -ReportType Html -Domain $Domain -Server $DC -Path ($Folder, $Domain + "_" + "GPOReport.html" -join "")
            Invoke-AuditGPOReport -Path ($Folder, $Domain + "_" + "GPOReport.xml" -join "") -Level 3 | Out-File ($Folder, $Domain + "_" + "GrouperResults.txt" -join "")
        }

        #Checking domain for Exchange PrivExchange vulnerability
        $PrivExchangeCheck = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\Microsoft Services\Exchange\"

            <#Reference:hhttps://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019
            https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/#>
            $ExchangeVersions = @{
                "15.02.0792.003" = "Exchange Server 2019 CU8, Not Vulnerable"
                "15.02.0721.002" = "Exchange Server 2019 CU7, Not Vulnerable"
                "15.02.0659.004" = "Exchange Server 2019 CU6, Not Vulnerable"
                "15.02.0595.003" = "Exchange Server 2019 CU5, Not Vulnerable"
                "15.02.0529.005" = "Exchange Server 2019 CU4, Not Vulnerable"
                "15.02.0464.005" = "Exchange Server 2019 CU3, Not Vulnerable"
                "15.02.0397.003" = "Exchange Server 2019 CU2, Not Vulnerable"
                "15.02.0330.005" = "Exchange Server 2019 CU1, Not Vulnerable"
                "15.02.0221.012" = "Exchange Server 2019 RTM, Vulnerable to PrivExchange!"
                "15.02.0196.000" = "Exchange Server 2019 Preview, Vulnerable to PrivExchange!"
                "15.01.2176.002" = "Exchange Server 2016 CU19, Not Vulnerable"
                "15.01.2106.002" = "Exchange Server 2016 CU18, Not Vulnerable"
                "15.01.2044.004" = "Exchange Server 2016 CU17, Not Vulnerable"
                "15.01.1979.003" = "Exchange Server 2016 CU16, Not Vulnerable"
                "15.01.1913.005" = "Exchange Server 2016 CU15, Not Vulnerable"
                "15.01.1847.003" = "Exchange Server 2016 CU14, Not Vulnerable"
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

            #Importing needed modules
            Import-Module "C:\Tools\PowerSploit\Recon\PowerView.ps1"

            #Identify instances of Active Directory Certificate Service
            $RootDSE = "DC=$($Domain.Replace('.', ',DC='))"
            $CAs = ([ADSI]"LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$RootDSE").Children

            $CertTemplates = @()

            # Dumping list of available certificates and adding to array
            foreach ($CA in $CAs) {
                $CertTemplates += $CA.certificateTemplates
            }


            $Certs = @()
            foreach ($CertTemplate in $CertTemplates) {
                $Certs += ([ADSI]"LDAP://CN=$CertTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$RootDSE")
            }

            # Convert Application Policy OID numbers to certificate types
            $AppPolicy = @{
                '1.3.6.1.5.5.7.3.1'        = 'Server Authentication'
                '1.3.6.1.5.5.7.3.3'        = 'Code Signing'
                '1.3.6.1.5.5.7.3.2'        = 'Client Authentication'
                '1.3.6.1.4.1.311.54.1.2'   = 'Remote Desktop'
                '1.3.6.1.4.1.311.76.6.1'   = 'Windows Update'
                '1.3.6.1.4.1.311.10.3.25'  = 'Windows Third Party Application Component'
                '1.3.6.1.4.1.311.10.3.23'  = 'Windows TCB Component'
                '1.3.6.1.4.1.311.76.3.1'   = 'Windows Store'
                '1.3.6.1.4.1.311.10.3.26'  = 'Windows Software Extension Verification'
                '1.3.6.1.4.1.311.10.3.21'  = 'Windows RT Verification'
                '1.3.6.1.4.1.311.10.3.20'  = 'Windows Kits Component'
                '1.3.6.1.4.1.311.60.3.3'   = 'No OCSP Failover to CRL'
                '1.3.6.1.4.1.311.60.3.2'   = 'Auto Update End Revocation'
                '1.3.6.1.4.1.311.60.3.1'   = 'Auto Update CA Revocation'
                '1.3.6.1.4.1.311.10.3.19'  = 'Revoked List Signer'
                '1.3.6.1.4.1.311.10.3.24'  = 'Protected Process Verification'
                '1.3.6.1.4.1.311.10.3.22'  = 'Protected Process Light Verification'
                '2.23.133.8.2'             = 'Platform Certificate'
                '1.3.6.1.4.1.311.76.8.1'   = 'Microsoft Publisher'
                '1.3.6.1.4.1.311.6.1.1'    = 'Kernel Mode Code Signing'
                '1.3.6.1.4.1.311.61.5.1'   = 'HAL Extension'
                '2.23.133.8.1'             = 'Endorsement Key Certificate'
                '1.3.6.1.4.1.311.61.4.1'   = 'Early Launch Antimalware Driver'
                '1.3.6.1.4.1.311.76.5.1'   = 'Dynamic Code Generator'
                '1.3.6.1.4.1.311.64.1.1'   = 'DNS Server Trust'
                '1.3.6.1.4.1.311.80.1'     = 'Document Encryption'
                '1.3.6.1.4.1.10.3.30'      = 'Disallowed List'
                '1.3.6.1.4.1.311.47.1.1'   = 'System Health Authentication'
                '1.3.6.1.4.1.311.20.2.2'   = 'IdMsKpScLogon'
                '1.3.6.1.4.1.311.20.2.1'   = 'ENROLLMENT_AGENT'
                '1.3.6.1.4.1.311.20.1'     = 'AUTO_ENROLL_CTL_USAGE'
                '1.3.6.1.4.1.311.21.5'     = 'KP_CA_EXCHANGE'
                '1.3.6.1.4.1.311.21.6'     = 'KP_KEY_RECOVERY_AGENT'
                '1.3.6.1.5.5.7.3.4'        = 'PKIX_KP_EMAIL_PROTECTION'
                '1.3.6.1.5.5.7.3.5'        = 'PKIX_KP_IPSEC_END_SYSTEM'
                '1.3.6.1.5.5.7.3.6'        = 'PKIX_KP_IPSEC_TUNNEL'
                '1.3.6.1.5.5.7.3.7'        = 'PKIX_KP_IPSEC_USER'
                '1.3.6.1.5.5.7.3.8'        = 'PKIX_KP_TIMESTAMP_SIGNING'
                '1.3.6.1.5.5.7.3.9'        = 'KP_OCSP_SIGNING'
                '1.3.6.1.5.5.8.2.2'        = 'IPSEC_KP_IKE_INTERMEDIATE'
                '1.3.6.1.4.1.311.10.3.1'   = 'KP_CTL_USAGE_SIGNING'
                '1.3.6.1.4.1.311.10.3.2'   = 'KP_TIME_STAMP_SIGNING'
                '1.3.6.1.4.1.311.10.3.5'   = 'WHQL_CRYPTO'
                '1.3.6.1.4.1.311.10.3.6'   = 'NT5_CRYPTO'
                '1.3.6.1.4.1.311.10.3.7'   = 'OEM_WHQL_CRYPTO'
                '1.3.6.1.4.1.311.10.3.8'   = 'EMBEDDED_NT_CRYPTO'
                '1.3.6.1.4.1.311.10.3.9'   = 'ROOT_LIST_SIGNER'
                '1.3.6.1.4.1.311.10.3.10'  = 'KP_QUALIFIED_SUBORDINATION'
                '1.3.6.1.4.1.311.10.3.11'  = 'KP_KEY_RECOVERY'
                '1.3.6.1.4.1.311.10.3.12'  = 'KP_DOCUMENT_SIGNING'
                '1.3.6.1.4.1.311.10.3.13'  = 'KP_LIFETIME_SIGNING'
                '1.3.6.1.4.1.311.10.5.1'   = 'DRM'
                '1.3.6.1.4.1.311.10.5.2'   = 'DRM_INDIVIDUALIZATION'
                '1.3.6.1.4.1.311.10.6.1'   = 'LICENSES'
                '1.3.6.1.4.1.311.10.6.2'   = 'LICENSE_SERVER'
                '1.3.6.1.4.1.311.10.3.4'   = 'KP_EFS'
                '1.3.6.1.4.1.311.10.3.4.1' = 'EFS_RECOVERY'
                '1.3.6.1.4.1.311.21.19'    = 'DS_EMAIL_REPLICATION'
                '1.3.6.1.4.1.311.10.12.1'  = 'ANY_APPLICATION_POLICY'
            }

            #Convert name flags to human readable values
            Function ConvertFrom-NameFlag {
                [cmdletbinding()]
                param (
                    [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                    [Int]
                    $Value
                )

                Begin {
                    $NameFlags = New-Object System.Collections.Specialized.OrderedDictionary
                    $NameFlags.Add("EnrolleeSuppliesSubject", 1) #This flag instructs the client to supply subject information in the certificate request
                    $NameFlags.Add("OldCertSuppliesSubjectAndAltName", 8) #This flag instructs the client to reuse values of subject name and alternative subject name extensions from an existing valid certificate when creating a certificate renewal request. Windows Server 2003, Windows Server 2008 - this flag is not supported.
                    $NameFlags.Add("EnrolleeSuppluiesAltSubject", 65536) #This flag instructs the client to supply subject alternate name information in the certificate request.
                    $NameFlags.Add("AltSubjectRequireDomainDNS", 4194304) #This flag instructs the CA to add the value of the requester's FQDN and NetBIOS name to the Subject Alternative Name extension of the issued certificate.
                    $NameFlags.Add("AltSubjectRequireDirectoryGUID", 16777216) #This flag instructs the CA to add the value of the objectGUID attribute from the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
                    $NameFlags.Add("AltSubjectRequireUPN" , 33554432) #This flag instructs the CA to add the value of the UPN attribute from the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
                    $NameFlags.Add("AltSubjectRequireEmail" , 67108864) #This flag instructs the CA to add the value of the e-mail attribute from the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
                    $NameFlags.Add("AltSubjectRequireDNS" , 134217728) #This flag instructs the CA to add the value obtained from the DNS attribute of the requestor's user object in Active Directory to the Subject Alternative Name extension of the issued certificate.
                    $NameFlags.Add("SubjectRequireDNSasCN" , 268435456) #This flag instructs the CA to add the value obtained from the DNS attribute of the requestor's user object in Active Directory as the CN in the subject of the issued certificate.
                    $NameFlags.Add("SubjectRequireEmail" , 536870912) #This flag instructs the CA to add the value of the e-mail attribute from the requestor's user object in Active Directory as the subject of the issued certificate.
                    $NameFlags.Add("SubjectRequireCommonName" , 1073741824) #This flag instructs the CA to set the subject name to the requestor's CN from Active Directory.
                    $NameFlags.Add("SubjectrequireDirectoryPath" , -2147483648) #This flag instructs the CA to set the subject name to the requestor's distinguished name (DN) from Active Directory.
                }

                Process {
                    $NameFlagValues = New-Object System.Collections.Specialized.OrderedDictionary

                    foreach ($NameFlag in $NameFlags.GetEnumerator()) {
                        if ( ($Value -band $NameFlag.value) -eq $NameFlag.value) {
                            $NameFlagValues.Add($NameFlag.Name, "$($NameFlag.Value)")
                        }
                    }

                    (($NameFlagValues.GetEnumerator()).Name -join ',')
                }
            }

            #Convert enrollment flags to human readable values
            Function ConvertFrom-EnrollmentFlag {
                [cmdletbinding()]
                param (
                    [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                    [Int]
                    $Value
                )

                Begin {
                    $EnrollmentFlags = New-Object System.Collections.Specialized.OrderedDictionary
                    $EnrollmentFlags.Add("IncludeSymmetricAlgorithms", 1) #This flag instructs the client and server to include a Secure/Multipurpose Internet Mail Extensions (S/MIME) certificate extension, as specified in RFC4262, in the request and in the issued certificate.
                    $EnrollmentFlags.Add("CAManagerApproval", 2) #This flag instructs the CA to put all requests in a pending state.
                    $EnrollmentFlags.Add("KraPublish", 4) #This flag instructs the CA to publish the issued certificate to the key recovery agent (KRA) container in Active Directory.
                    $EnrollmentFlags.Add("DsPublish", 8) #This flag instructs clients and CA servers to append the issued certificate to the userCertificate attribute, as specified in RFC4523, on the user object in Active Directory.
                    $EnrollmentFlags.Add("AutoenrollmentCheckDsCert", 16) #This flag instructs clients not to do autoenrollment for a certificate based on this template if the user's userCertificate attribute (specified in RFC4523) in Active Directory has a valid certificate based on the same template.
                    $EnrollmentFlags.Add("Autoenrollment", 32) #This flag instructs clients to perform autoenrollment for the specified template.
                    $EnrollmentFlags.Add("ReenrollExistingCert", 64) #This flag instructs clients to sign the renewal request using the private key of the existing certificate
                    $EnrollmentFlags.Add("RequireUserInteraction", 256) #This flag instructs the client to obtain user consent before attempting to enroll for a certificate that is based on the specified template.
                    $EnrollmentFlags.Add("RemoveInvalidFromStore", 1024) #This flag instructs the autoenrollment client to delete any certificates that are no longer needed based on the specific template from the local certificate storage
                    $EnrollmentFlags.Add("AllowEnrollOnBehalfOf", 2048) #This flag instructs the server to allow enroll on behalf of (EOBO) functionality.
                    $EnrollmentFlags.Add("IncludeOcspRevNoCheck", 4096) #This flag instructs the server to not include revocation information and add the id-pkix-ocsp-nocheck extension, as specified in [RFC2560] section 4.2.2.2.1, to the certificate that is issued.
                    $EnrollmentFlags.Add("ReuseKeyTokenFull", 8192) #This flag instructs the client to reuse the private key for a smart card–based certificate renewal if it is unable to create a new private key on the card
                    $EnrollmentFlags.Add("NoRevocationInformation", 16384) #This flag instructs the server to not include revocation information in the issued certificate.
                    $EnrollmentFlags.Add("BasicConstraintsInEndEntityCerts", 32768) #This flag instructs the server to include Basic Constraints extension in the end entity certificates.
                    $EnrollmentFlags.Add("IgnoreEnrollOnReenrollment", 65536) #This flag instructs the CA to ignore the requirement for Enroll permissions on the template when processing renewal requests.
                    $EnrollmentFlags.Add("IssuancePoliciesFromRequest", 131072) #This flag indicates that the certificate issuance policies to be included in the issued certificate come from the request rather than from the template. The template contains a list of all of the issuance policies that the request is allowed to specify; if the request contains policies that are not listed in the template, then the request is rejected.
                }

                Process {
                    $NameFlagValues = New-Object System.Collections.Specialized.OrderedDictionary

                    foreach ($NameFlag in $NameFlags.GetEnumerator()) {
                        if ( ($Value -band $NameFlag.value) -eq $NameFlag.value) {
                            $NameFlagValues.Add($NameFlag.Name, "$($NameFlag.Value)")
                        }
                    }

                    (($NameFlagValues.GetEnumerator()).Name -join ',')
                }
            }

            #Convert private key flags to human readable values
            Function ConvertFrom-PrivateKeyFlag {
                [cmdletbinding()]
                param (
                    [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
                    [Int]
                    $Value
                )

                Begin {
                    $PrivateKeyFlags = New-Object System.Collections.Specialized.OrderedDictionary
                    $PrivateKeyFlags.Add("RequireKeyArchival" , 1)
                    $PrivateKeyFlags.Add("AllowKeyExport", 16)
                    $PrivateKeyFlags.Add("RequireStrongProtection", 32)
                    $PrivateKeyFlags.Add("ReuseKeysRenewal", 128)
                    $PrivateKeyFlags.Add("UseLegacyProvider", 256)
                    $PrivateKeyFlags.Add("TrustOnUse", 512)
                    $PrivateKeyFlags.Add("ValidateCert", 1024)
                    $PrivateKeyFlags.Add("ValidateKey", 2048)
                    $PrivateKeyFlags.Add("Preferred", 4096)
                    $PrivateKeyFlags.Add("Required", 8192)
                    $PrivateKeyFlags.Add("WithoutPolicy", 16384)
                }

                Process {

                    $PrivateKeyFlagValues = New-Object System.Collections.Specialized.OrderedDictionary

                    foreach ($PrivateKeyFlag in $PrivateKeyFlags.GetEnumerator()) {
                        if ( ($Value -band $PrivateKeyFlag.value) -eq $PrivateKeyFlag.value) {
                            $PrivateKeyFlagValues.Add($PrivateKeyFlag.Name, "$($PrivateKeyFlag.Value)")
                        }
                    }

                    (($PrivateKeyFlagValues.GetEnumerator()).Name -join ',')

                }
            }

            # Extract values to csv
            foreach ( $Cert in $Certs) {
                $CertProperties = [ordered]@{
                    'Name'               = ($Cert.displayName).ToString()
                    'Certificate Type'   = ($AppPolicy[($Cert.'msPKI-Certificate-Application-Policy')] -join ', ').ToString()
                    'Key Size'           = ($Cert.'msPKI-Minimal-Key-Size').ToString()
                    'Subject Name Flags' = ($Cert.'msPKI-Certificate-Name-Flag' | ConvertFrom-NameFlag)
                    'Enrollement Flags'  = ($Cert.'msPKI-Enrollment-Flag' | ConvertFrom-EnrollmentFlag)
                    'Private Key Flags'  = ($Cert.'msPKI-Private-Key-Flag' | ConvertFrom-PrivateKeyFlag)
                    'When Created'       = ($Cert.'whenCreated').ToString()
                    # Identify enrollment privileges. Remove entries for Domain/Enterprise Admins
                    'Enroll Privileges'  = ((Get-ObjectAcl -SearchBase $cert.Path | Where-Object { $_.SecurityIdentifier -notlike "*-51[2,9]" -and $_.ObjectAceType -eq "0e10c968-78fb-11d2-90d4-00c04f79dc55" }).SecurityIdentifier | ConvertFrom-SID) -join ', '
                }

                $object = New-Object -TypeName PSObject -Property $CertProperties
                $object | Export-CSV ($Folder, $Domain + "_" + "certificates.csv" -join "") -Append -NoTypeInformation
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
                "--scanner share --server $Domain"
                "--scaner localadmin --server $Domain"
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

        #Running PowerUPSQL commands
        $PowerUPSQLScriptBlock = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Folder = "$Path\$ClientName\$Domain\PowerUPSQL\"

            #Importing needed modules
            Import-Module "C:\tools\PowerUpSQL\PowerUpSQL.psm1"

            $MSSQLServers = Get-SQLInstanceDomain

            foreach ($Server in $MSSQLServers) {
                $MSSQLProperties = [ordered]@{
                    'Description'   = $Server.Description
                    'ComputerName'  = $Server.ComputerName
                    'IPAddress'     = ($Server.ComputerName | Get-IPAddress).IPAddress
                    'Instance'      = $Server.Instance
                    'DomainAccount' = $Server.DomainAccount
                    'Service'       = $Server.Service
                    'Spn'           = $Server.SPN
                }

                $object = New-Object -TypeName PSObject -Property $MSSQLProperties
                $object | Export-Csv ($Folder, $Domain + "_" + "MSSQLServers.csv" -join "") -NoTypeInformation -Append
            }

            #Identify MSSQL sysadmin privileges with the current domain account
            $Targets = $MSSQLServers | Get-SQLConnectionTestThreaded -Verbose -Threads 10

            $Targets | Invoke-SQLOSCmd -Verbose -Command "Whoami" -Threads 10 | Export-Csv ($Folder, $Domain + "_" + "MSSQLServers_xpcmdshell.csv" -join "") -NoTypeInformation
        }

        $QuickScanMSSQL = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Username = $args[3]
            $Folder = "$Path\$ClientName\$Domain\QuickScan\$UserName"

            #Create User Folder
            if ((Test-Path $args) -eq $false)
            {
                Write-Host -ForegroundColor Green "[+] Creating $Folder"
                mkdir -Path $Folder | Out-Null
            }

            #Importing PowerUPSQL PS Module
            Write-Host -ForegroundColor Green "[+] Importing PS Modules"
            Import-Module "C:\tools\PowerUpSQL\PowerUpSQL.psm1"

            $Targets = Get-SQLInstanceDomain -verbose | Get-SQLConnectionTestThreaded -Verbose -Threads 10
            $Targets | Invoke-SQLOSCmd -Verbose -Command "Whoami" -Threads 10 | Export-Csv ($Folder, $Domain + "_" + "MSSQLServers_xpcmdshell.csv" -join "") -NoTypeInformation -NoTypeInformation
            }

        $QuickScanPingCastle = {
            $ClientName = $args[0]
            $Path = $args[1]
            $Domain = $args[2]
            $Username = $args[3]
            $Folder = "$Path\$ClientName\$Domain\QuickScan\$UserName"
            
            #Create User Folder
            if ((Test-Path $args) -eq $false)
            {
                Write-Host -ForegroundColor Green "[+] Creating $Folder"
                mkdir -Path $Folder | Out-Null
            }

            #PingCastle scanner commands
            $Arguments = @(
                "--scanner share --server $Domain"
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
                    Start-Job -ScriptBlock $PowerUPSQLScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name PowerUPSQL_$Domain | Out-Null
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
                    Start-Job -ScriptBlock $ADCS -ArgumentList $ClientName, $Path, $Domain -Name ADCS_$Domain | Out-Null
                }
            }

            "PowerView" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting PowerView Enum for $Domain"
                    Start-Job -ScriptBlock $PowerViewScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name PowerView_$Domain | Out-Null
                }
            }

            "PowerUPSQL" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting PowerUPSQL Enum for $Domain"
                    Start-Job -ScriptBlock $PowerUPSQLScriptBlock -ArgumentList $ClientName, $Path, $Domain -Name PowerUPSQL_$Domain | Out-Null
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

            "QuickScan" {
                foreach ($Domain in $Domains) {
                    Write-Host -ForegroundColor Green "[+] Starting QuickScan PingCastle AD Enum for $Domain as $Username"
                    Start-Job -ScriptBlock $QuickScanPingCastle -ArgumentList $ClientName, $Path, $Domain, $UserName -Name QuickScan_PingCastle_$Domain | Out-Null

                    Write-Host -ForegroundColor Green "[+] Starting QuickScan PowerUPSQL AD Enum for $Domain as $Username"
                    Start-Job -ScriptBlock $QuickScanMSSQL -ArgumentList $ClientName, $Path, $Domain, $UserName -Name QuickScan_MSSQL_$Domain | Out-Null
                }
            }
        }
    }
}