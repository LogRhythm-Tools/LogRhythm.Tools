using namespace System
using namespace System.IO

<#
.SYNOPSIS
    End to end testing of the LrtBuilder module, from build to publish.
.PARAMETER NewConfig
    Removes the existing configuration so that a new one will be generated
    by Setup.ps1.
.PARAMETER Reset
    If the Reset switch is provided, then the entire contents of the LogRhythm.Tools configuration directory
    will be backed up to tests\Lrt.Publisher\backup\ and the configuration directory in %LocalAppData% will
    be removed so that it can be re-created by the Setup script.
.PARAMETER RestoreKeys
    If the RestoreKeys switch is set, all xml files that were backed up from LogRhythm.Tools configuration
    will be restored once the test has completed.
.INPUTS
    None
.OUTPUTS
    (1) The resulting release archive that would be published to GitHub for general distribution.
    (2) An extracted directory containing (1)
.NOTES
    Test Data: consists of the output of Publish-LrtBuild
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [switch] $NewConfig,

    [Parameter(Mandatory = $false, Position = 0)]
    [switch] $Reset,

    [Parameter(Mandatory = $false, Position = 1)]
    [switch] $RestoreKeys
)



#region: Load Lrt.Builder & Get-LrtRepoInfo                                                        
# Load Lrt.Builder
$RepoRoot = (([DirectoryInfo]::new($PSScriptRoot)).Parent).Parent
$BuildModulePath = Join-Path -Path $RepoRoot.FullName -ChildPath "build\Lrt.Builder.psm1"
Get-Module Lrt.Builder | Remove-Module -Force
Import-Module $BuildModulePath

# Repo Info
$RepoInfo = Get-LrtRepoInfo


# Config Directory
$ConfigDirPath = Join-Path -Path ([Environment]::GetFolderPath("LocalApplicationData")) -ChildPath $RepoInfo.ModuleInfo.Name

# Backup location
$T_BKP = Join-Path -Path $PSScriptRoot -ChildPath "backup"

# Data = Release.zip extracted files
$T_DATA = Join-Path -Path $PSScriptRoot -ChildPath "data"
$T_DATA_FILES = Join-Path -Path $T_DATA -ChildPath "*"


# Test Data directories aren't tracked, so create if not found.
if (! (Test-Path $T_DATA)) {
    New-Item -Path $T_DATA -Name "data" -ItemType Directory | Out-Null
}
# Test Backup directories aren't tracked, so create if not found.
if (! (Test-Path $T_BKP)) {
    New-Item -Path $T_BKP -Name "backup" -ItemType Directory | Out-Null
}
#endregion



#region: Backup                                                                                    
if ($Reset) {
    # Backup current config
    $_ts = ([datetime]::now).ToString('yyyy-MM-dd-hh-mm')
    $BackupPath = New-Item -Path $T_BKP -ItemType Directory -Name $_ts
    $BackupItems = Get-ChildItem -Path $ConfigDirPath -Recurse
    try {
        Write-Host "Saving existing configuration to: $($BackupPath.FullName)"
        $BackupItems | Copy-Item -Destination $BackupPath.FullName
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }

    # Remove config
    try {
        Remove-Item -Path $ConfigDirPath -Recurse -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Faileld to remove existing configuration at $ConfigDirPath"
    }
}


# Remove config file only - no backup.
if ($NewConfig) {
    $ConfigFilePath = $ConfigDirPath | Join-Path -ChildPath "LogRhythm.Tools.json"
    Remove-Item -Path $ConfigFilePath -Force -ErrorAction SilentlyContinue
}
#endregion

# Clean out old test data
Remove-Item -Recurse -Path $T_DATA_FILES -Force -ErrorAction SilentlyContinue

# New Build
$TestRelease = New-LrtBuild -Version 1.0.0 -ReleaseTag (New-LrtReleaseTag) | Publish-LrtBuild -Destination $T_DATA -PassThru

# Extract results
Expand-Archive -Path $TestRelease.FullName -DestinationPath "$T_DATA\lrt-install"

# Run Setup
try {
    Invoke-Expression -Command "$T_DATA\lrt-install\Setup.ps1" -ErrorAction Stop
}
catch {
    Write-Host "Error occured while executing Setup.ps1"
    $PSCmdlet.ThrowTerminatingError($PSItem)
}

# Restore Keys
if ($RestoreKeys -and $Reset) {
    Write-Host "Restoring API Keys to $ConfigDirPath"
    Get-ChildItem -Path $BackupPath -Filter *.xml | Copy-Item -Destination $ConfigDirPath
    
}
