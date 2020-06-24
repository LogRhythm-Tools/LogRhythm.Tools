using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrtInstallerInfo {
    <#
    .SYNOPSIS
        Get-LrtInstallerInfo will provide general information about any existing
        LogRhythm.Tools modules installed on the current host.
    .INPUTS
        None
    .OUTPUTS
        [InstallInfo]           [PSObject]
        ├── BaseDir             [string] Base of the release dir
        ├── ModuleInfo          [PSObject] ModuleInfo.json (loaded)
        ├── ModuleInfoPath      [string] Path to ModuleInfo.json
        ├── User           
        │   ├── Path            [string] $HOME\Documents\WindowsPowerShell\Modules
        │   ├── InstallPath     [string] Path + LogRhythm.Tools
        │   ├── Installed       [bool] Is the module installed for this scope
        │   └── Versions        [List[string]] A list of the installed versions
        └── System
        │   ├── Path            [string] C:\Program Files\WindowsPowerShell\Modules
        │   ├── InstallPath     [string] Path + LogRhythm.Tools
        │   ├── Installed       [bool] Is the module installed for this scope
        │   └── Versions        [List[string]] A list of the installed versions


    .EXAMPLE
        PS> Get-LrtInstallerInfo
        ---
        User   : @{Path=C:\Users\genec\Documents\WindowsPowerShell\Modules\LogRhythm.Tools; Installed=True; HighestVer=0.9.9}
        System : @{Path=C:\Program Files\WindowsPowerShell\Modules\LogRhythm.Tools; Installed=False; HighestVer=0}
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param( )


    # Output Object Structure
    $Info = [PSCustomObject]@{
        BaseDir        = $null
        CommonFiles    = $null
        ModuleInfo     = $null
        ModuleInfoPath = ""
        ConfigTemplatePath = ""
        
        InstallScopes  = [PSCustomObject]@{
            User = [PSCustomObject]@{
                Path = ""
                InstallPath = ""
                Installed = $false
                Versions = [List[string]]::new()
            }
            
            System = [PSCustomObject]@{
                Path = ""
                InstallPath = ""
                Installed = $false
                Versions = [List[string]]::new()
            }      
        }
    }


    # Get BaseDir
    $BaseDir = (([DirectoryInfo]::new($PSScriptRoot)).Parent).Parent
    $Info.BaseDir = $BaseDir
    $Info.CommonFiles = @(Get-ChildItem -Path (Join-Path $BaseDir.FullName "common"))

    # Get ModuleInfo
    $_modInfoPath = Join-Path -Path $BaseDir.FullName -ChildPath "ModuleInfo.json"
    $ModuleInfo   = Get-Content -Path $_modInfoPath | ConvertFrom-Json
    $Info.ModuleInfo  = $ModuleInfo
    $Info.ModuleInfoPath = $_modInfoPath
    $Info.ConfigTemplatePath = Join-Path -Path $BaseDir.FullName -ChildPath "common\"

    # System: Path / InstallPath
    $SystemScope = $Info.InstallScopes.System
    $SystemScope.Path = Join-Path `
        -Path $Env:ProgramFiles `
        -ChildPath "WindowsPowerShell\Modules"
    $SystemScope.InstallPath = Join-Path `
        -Path $SystemScope.Path `
        -ChildPath $Info.ModuleInfo.Name


    # User: Path / InstallPath
    $UserScope = $Info.InstallScopes.User
    $UserScope.Path = Join-Path `
        -Path $Env:HOME `
        -ChildPath "Documents\WindowsPowerShell\Modules"
        $UserScope.InstallPath = Join-Path `
        -Path $UserScope.Path `
        -ChildPath $Info.ModuleInfo.Name
        



    # User: Check if module is installed & create version list
    if (Test-Path $UserScope.InstallPath) {
        $UserInstalls = Get-ChildItem -Path $UserScope.InstallPath -Directory

        if ($UserInstalls.Count -gt 0) {
            $UserScope.Installed = $true
            $UserInstalls | ForEach-Object { $UserScope.Versions.Add($_.Name) }            
        }
    }

    # System: Check if module is installed & create version list
    if (Test-Path $SystemScope.InstallPath) {
        $SystemInstalls = Get-ChildItem -Path $SystemScope.InstallPath -Directory

        if ($SystemInstalls.Count -gt 0) {
            $SystemScope.Installed = $true
            $SystemInstalls | ForEach-Object { $SystemScope.Versions.Add($_.Name) }            
        }
    }
    
 
    return $Info
}