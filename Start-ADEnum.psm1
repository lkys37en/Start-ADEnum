$Functions = @( Get-ChildItem -Path $PSScriptRoot\Functions\*.ps1 -ErrorAction SilentlyContinue )

foreach ($Function in $Functions) {
    try {
        Import-Module $Function
    }
    
    catch {
        Write-Error -Message "Failed to import function $($Function): $_"
    }
   
}