Function Install-Tools {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("PowerSploit", "BloodHound", "Grouper", "PingCastle")]
        [String]
        $Tool
    )
    Begin {
        #Github tools url
        $PowerSploitUrl = "https://github.com/PowershellMafia/PowerSploit.git"
        $BloodHountUrl = "https://github.com/BloodHoundAD/BloodHound.git"
        $GrouperUrl = "https://github.com/l0ss/Grouper.git"

        #Choco tools variable
        $ChocoTools = @(
            "git"
        )

        #Tools folder
        $ToolsFolder = "C:\Tools"

        if (!(Test-Path $ToolsFolder)) {
            Write-Host -ForegroundColor Green "[+] Creating tools directory"
            mkdir $ToolsFolder | Out-Null
        }

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

        switch ($Tool) {
            "PowerSploit" {
                Write-Host -ForegroundColor Green "[+] Cloning PowerSploit into $ToolsFolder and switching to dev branch"
                Set-Location $ToolsFolder ; git clone -q $PowerSploitUrl;
                Set-Location $ToolsFolder\PowerSploit; git checkout -q dev ; git pull -q
            }

            "BloodHound" {
                Write-Host -ForegroundColor Green "[+] Cloning BloodHound directory to $ToolsFolder"
                Set-Location $ToolsFolder ; git clone -q $BloodHountUrl
            }

            "Grouper" {
                Write-Host -ForegroundColor Green "[+] Cloning Grouper directory to $ToolsFolder"
                Set-Location $ToolsFolder ; git clone -q $GrouperUrl
            }
            "PingCastle" {
                $PingCastle = ((Invoke-WebRequest https://github.com/vletoux/pingcastle/releases -UseBasicParsing).Links | Where-Object -Property outerHTML -like ("*.zip*")).href | Select-Object -First 1
                $PingCastleUrl = "https://github.com$PingCastle"
                $PingCastleZip = $PingCastle -split '/' | Select-Object -Last 1
                $PingCastleZipDst = "C:\tools\$PingCastleZip"
                $PingCastleDst = "C:\tools\PingCastle"

                Write-Host -ForegroundColor Green "[+] Downloading PingCastle"
                Invoke-WebRequest -Uri $PingCastleUrl -OutFile $PingCastleZipDst

                Write-Host -ForegroundColor Green "[+] Expanding PingCastle Archive"
                Expand-Archive $PingCastleZipDst -DestinationPath $PingCastleDst
                Remove-item $PingCastleZipDst

                Write-Host -ForegroundColor Green "[+] Modifying path variable"
                [Environment]::SetEnvironmentVariable
                ("C:\tools\PingCastle", $env:Path, [System.EnvironmentVariableTarget]::Machine)
            }
        }
    }
}
