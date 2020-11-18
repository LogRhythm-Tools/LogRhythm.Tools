using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrtConfig {
    <#
    .SYNOPSIS
        Creates [LogRhythm.Tools] configuration directory in %LocalAppData% (if it does not exist)
        Copies template copy of [LogRhythm.Tools.json] to %LocalAppData%\LogRhythm.Tools (if it does not exist)
    .DESCRIPTION
        Originally this command did much more, but now all it does is perform the
        initial creation/copy steps to get a config in place for the user.
    .INPUTS
        None
    .OUTPUTS
        [Object] Configuration
            Dir   =>  [DirectoryInfo] Config Directory
            File  =>  [FileInfo]      Config File
    .EXAMPLE
        PS C:\> New-LrtConfig
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param( )


    # Load module information
    $InstallerInfo = Get-LrtInstallerInfo
    $ModuleInfo = $InstallerInfo.ModuleInfo
    $LocalAppData = [Environment]::GetFolderPath("LocalApplicationData")


    # Configuration Dir: %LocalAppData%\LogRhythm.Tools\
    $ConfigDirPath = Join-Path `
        -Path $LocalAppData `
        -ChildPath $ModuleInfo.Name

    # Create Config Dir (if it does not exist)
    if (! (Test-Path -Path $ConfigDirPath)) {
        New-Item -Path $LocalAppData `
            -Name $ModuleInfo.Name -ItemType Directory | Out-Null
        Write-Verbose "Created configuration directory at $ConfigDirPath"
    }

    # Get any files contained in the ConfigDir and put their names in a list.
    # We will add any that are missing.  This allows users to keep their config
    # if they are doing a new install.
    $ExistingCommonFiles = [List[string]]::new()
    Get-ChildItem -Path $ConfigDirPath | ForEach-Object { $ExistingCommonFiles.Add($_.Name) }


    # Copy any missing common files to $ConfigDirPath
    foreach ($file in $InstallerInfo.CommonFiles) {
        if (! $ExistingCommonFiles.Contains($file.Name)) {
            Copy-Item -Path $file.FullName -Destination $ConfigDirPath
        }
    }

    # Config File Destination Path - for easy loading by other scripts
    $ConfigFilePath = Join-Path -Path $ConfigDirPath -ChildPath $ModuleInfo.Conf
    

    $Return = [PSCustomObject]@{
        ConfigDir = [DirectoryInfo]::new($ConfigDirPath)
        ConfigFilePath = [DirectoryInfo]::new($ConfigFilePath)
        Config = Get-Content -Path $ConfigFilePath -Raw | ConvertFrom-Json
    }
    return $Return
}