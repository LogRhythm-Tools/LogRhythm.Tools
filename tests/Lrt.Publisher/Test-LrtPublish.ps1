using namespace System
using namespace System.IO

<#
.SYNOPSIS
    End to end testing of the LrtBuilder module, from build to publish.
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
    [switch] $Reset,

    [Parameter(Mandatory = $false, Position = 1)]
    [switch] $BackupConfig,

    [Parameter(Mandatory = $false , Position = 2)]
    [ValidateNotNull()]
    [DirectoryInfo] $Destination
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


# Will contain result of Publish-LrtBuild
$T_DATA = Join-Path -Path $PSScriptRoot -ChildPath "data"
# Everything inside T_DATA
$T_CONTENTS = Join-Path -Path $T_DATA -ChildPath "*"

# Tetst Data directories aren't tracked, so create one if ! exist
if (! (Test-Path $T_DATA)) {
    New-Item -Path $T_DATA -Name "data" -ItemType Directory | Out-Null
}
#endregion



#region: Backup                                                                                    
if ($BackupConfig) {
    $BackupPath = $Destination.FullName
    if (! $Destination.Exists) {
        Write-Warning "Destination directory [$BackupPath] not found. Saving to [Desktop]"
        $BackupPath = [Environment]::GetFolderPath("Desktop")
    }
    try {
        Copy-Item -Path $ConfigDirPath -Destination $BackupPath
        Write-Host "Existing configuration saved to $BackupPath"
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}
#endregion



#region: Reset                                                                                     
if ($Reset) {
    try {
        Remove-Item -Path $ConfigDirPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Failed to remove existing Lrt configuration from $ConfigDirPath" -ForegroundColor Yellow
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
}
#endregion



#region: Clean                                                                                     
try {
    Remove-Item -Recurse -Path $T_CONTENTS -Force -ErrorAction SilentlyContinue
}
catch {
    Write-Host "Failed to remove old test data. Resolve error and try again." -ForegroundColor Yellow
    $PSCmdlet.ThrowTerminatingError($PSItem)
}
#endregion


#region: Publish and Run Setup.ps1                                                                 
$TestRelease = New-LrtBuild -Version 1.0.0 -ReleaseTag (New-LrtReleaseTag) | Publish-LrtBuild -Destination $T_DATA -PassThru

# Extract the results
Expand-Archive -Path $TestRelease.FullName -DestinationPath "$T_DATA\lrt-install"

# Run Setup!
Invoke-Expression -Command "$T_DATA\lrt-install\Setup.ps1"
#endregion