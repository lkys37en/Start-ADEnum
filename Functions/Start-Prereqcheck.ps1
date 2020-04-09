Function Start-PrereqCheck {
    Begin {
        # Windows 10 1809 build
        $1809Build = "17763"

        # Windows 10 1903 build
        $1903Build = "18362"
        
        # Windows 10 1909 build
        $1909Build = "18363"

        # Get running Windows build
        $WindowsBuild = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber

        #Defender variable
        $Defender = (Get-MpPreference).DisableRealtimeMonitoring

        #RSAT Check Variable
        $RSATInstall = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat*" -AND $_.State -eq "NotPresent" }
                
        #Module Check Variable
        $Modules = @(
            "C:\Tools\PowerSploit\Recon\PowerView.ps1"
            "C:\Tools\PowerSploit\Exfiltration\Get-GPPPassword.ps1"
            "C:\Tools\BloodHound\Ingestors\SharpHound.ps1"
            "C:\Tools\Grouper\grouper.psm1"
            "C:\Tools\PingCastle\PingCastle.exe"
        )
        
        # Check for administrative rights
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error -Message "The script requires elevation"
            break
        }

        #Check if using correct version of Windows
        if (!($WindowsBuild -eq $1809Build -OR $WindowsBuild -eq $1903Build -OR $WindowsBuild -eq $1909Build)) {
            throw "[-] Current buidnumber $WindowsBuild is not compatible. Please upgrade to Windows 10 1809 or 1903"
        }

        #Disabling Defender real time protection
        if ($Defender -eq $true) {
            Write-Host -ForegroundColor Green "[*] Defender real time protection is already disabled"
        }

        else {
            Write-Host -ForegroundColor Green "[+] Disabling Defender real time protection"
            try {
                Set-MpPreference -DisableRealtimeMonitoring $true | Out-Null
            }
            catch {
                throw "Failed disable windows defender real time protection $($_.Exception.Message)"
            }
        }
    }

    Process {
        #Uitlizes the Install-Tool function to install modules if not already present.
        foreach ($Module in $Modules) {
            try {
                if (!(Test-Path -Path $Module)) {
                    Install-Tools -Tool ($Module -split '\\' | Select-Object -Skip 2 | Select-Object -First 1)
                }
            }

            catch {
                throw "An error has occurred. $($_.Exception.Message)"
            }
        }

        #Install RSAT tools
        if ($RSATInstall -ne $null) {
            Write-Host -ForegroundColor Green "[+] Installing all available RSAT features"
            foreach ($Item in $RSATInstall) {
                $RsatItem = $Item.Name
                try {
                    Add-WindowsCapability -Online -Name $RsatItem | Out-Null
                }
                catch [System.Exception] {
                    throw "[*] Failed to add $RsatItem to Windows $($_.Exception.Message)"
                }
            }
        }

        else {
            Write-Host -ForegroundColor Green "[*] All RSAT features seems to be installed already"
        }
    }
}
