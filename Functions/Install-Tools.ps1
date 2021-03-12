Function Install-Tools {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("PowerSploit", "BloodHound", "Grouper", "PingCastle","PowerUPSQL")]
        [String]
        $Tool
    )

    Begin {
        #Github tools url
        $PowerSploitUrl = "https://github.com/PowershellMafia/PowerSploit.git"
        $BloodHountUrl = "https://github.com/BloodHoundAD/BloodHound.git"
        $GrouperUrl = "https://github.com/l0ss/Grouper.git"
        $PowerUpSQLUrl= "https://github.com/NetSPI/PowerUpSQL.git"

        #Chocolately tools variable
        $ChocoTools = @(
            "git"
        )

        #Tools folder
        $ToolsFolder = "C:\Tools"

        #Create tools directory if it doesn't already exist
        if (!(Test-Path $ToolsFolder)) {
            Write-Host -ForegroundColor Green "[+] Creating tools directory"
            mkdir $ToolsFolder | Out-Null
        }

        #Install chocolately if not already installed
        if (!(Test-Path $ENV:ChocolateyInstall)) {
            Write-Host -ForegroundColor Green "[+] Installing Chocolately"
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
            }
            catch {
                throw "Failed to install chocolately $($_.Exception.Message)"
            }
        }
    }

    Process {
        #Install all chocoaltely tools
        foreach ($ChocoTool in $ChocoTools) {
            try {
                $Installed = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where { $_.DisplayName -like "*$ChocoTool*" }) -ne $null
                If (!($Installed)) {
                    Write-Host -ForegroundColor Green "[+] Installing $ChocoTool"
                    Start-Process -Wait choco -ArgumentList "install $ChocoTool -y -f "
                }
            }

            catch {
                throw "An error has occurred  $($_.Exception.Message)"
            }
        }

        #Switch statement to install specific tool. This section is started from the Start-PreReqCheck function
        switch ($Tool) {
            "PowerSploit" {
                if (!(Test-Path "$ToolsFolder\PowerSploit")) {
                    try {
                        #Downloads PowerSpoit Dev branch if the PowerSploit directory doesn't exist
                        Write-Host -ForegroundColor Green "[+] Cloning PowerSploit into $ToolsFolder and switching to dev branch"
                        Set-Location $ToolsFolder ; git clone -q $PowerSploitUrl;
                        Set-Location $ToolsFolder\PowerSploit; git checkout -q dev ; git pull -q
                    }

                    catch {
                        throw "An error has occurred  $($_.Exception.Message)"
                    }
                }

                else {
                    #Performs Git pull on PowerSploit directory if it already exists
                    Write-Host -ForegroundColor Green "[+] PowerSploit already downloaded, performing git pull"
                    Set-Location "$ToolsFolder\PowerSploit" ; git pull | Out-Null
                }
            }

            "BloodHound" {
                if (!(Test-Path "$ToolsFolder\BloodHound")) {
                    try {
                        #Downloads PowerSpoit Dev branch if the PowerSploit directory doesn't exist
                        Write-Host -ForegroundColor Green "[+] Cloning BloodHound directory to $ToolsFolder"
                        Set-Location $ToolsFolder ; git clone -q $BloodHountUrl
                    }

                    catch {
                        throw "An error has occurred  $($_.Exception.Message)"
                    }
                }

                else {
                    Write-Host -ForegroundColor Green "[+] PowerSploit already downloaded, performing git pull"
                    Set-Location "$ToolsFolder\Bloodhound" ; git pull | Out-Null
                }
            }

            "Grouper" {
                if (!(Test-Path "$ToolsFolder\Grouper")) {
                    try {
                        Write-Host -ForegroundColor Green "[+] Cloning Grouper directory to $ToolsFolder"
                        Set-Location $ToolsFolder ; git clone -q $GrouperUrl
                    }

                    catch {
                        throw "An error has occurred  $($_.Exception.Message)"
                    }
                }

                else {
                    Write-Host -ForegroundColor Green "[+] Grouper already downloaded, performing git pull"
                    Set-Location "$ToolsFolder\Grouper" ; git pull | Out-Null
                }
            }

            "PowerUPSQL" {
                if (!(Test-Path "$ToolsFolder\PowerUpSQL")) {
                    try {
                        Write-Host -ForegroundColor Green "[+] Cloning PowerUPSQL directory to $ToolsFolder"
                        Set-Location $ToolsFolder ; git clone -q $PowerUpSQLUrl
                    }

                    catch {
                        throw "An error has occurred  $($_.Exception.Message)"
                    }
                }

                else {
                    Write-Host -ForegroundColor Green "[+] PowerUPSQL already downloaded, performing git pull"
                    Set-Location "$ToolsFolder\PowerUpSQL" ; git pull | Out-Null
                }
            }

            "PingCastle" {
                if (!(Test-Path "$ToolsFolder\PingCastle")) {
                    $PingCastle = ((Invoke-WebRequest https://github.com/vletoux/pingcastle/releases -UseBasicParsing).Links | Where-Object -Property outerHTML -like ("*.zip*")).href | Select-Object -First 1
                    $PingCastleUrl = "https://github.com$PingCastle"
                    $PingCastleZip = $PingCastle -split '/' | Select-Object -Last 1
                    $PingCastleZipDst = "$ToolsFolder\$PingCastleZip"
                    $PingCastleDst = "$ToolsFolder\PingCastle"

                    Write-Host -ForegroundColor Green "[+] Downloading PingCastle to $ToolsFolder"
                    Invoke-WebRequest -Uri $PingCastleUrl -OutFile $PingCastleZipDst

                    Write-Host -ForegroundColor Green "[+] Expanding PingCastle Archive"
                    Expand-Archive $PingCastleZipDst -DestinationPath $PingCastleDst
                    Remove-item $PingCastleZipDst
                }
            }
        }
    }
}
