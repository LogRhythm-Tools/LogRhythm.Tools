using namespace System
using namespace System.IO

Function Get-LrtRepoInfo {
    <#
    .SYNOPSIS
        Gets info aout directory structure and module information for LogRhythm.Tools
        for use in building / publishing the module.
    .INPUTS
        None
    .OUTPUTS
        ----------------------------------------
        [PSCustomObject] ModuleInfo
        ----------------------------------------
        RepoBaseDir : [DirectoryInfo]
        DistDir     : [DirectoryInfo]
        BuildDir    : [DirectoryInfo]
        ReleasesDir : [DirectoryInfo]
        SrcDir      : [DirectoryInfo]
        ModuleInfo  : [PSCustomObject]

    .EXAMPLE
        > $RepoInfo = Get-LrtRepoInfo
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param( )

    # Output Object Structure
    $RepoInfo = [PSCustomObject]@{
        RepoBaseDir =   $null
        DistDir     =   $null
        BuildDir    =   $null
        ReleasesDir =   $null
        SrcDir      =   $null
        ModuleInfo  =   $null
        BuildInfo   =   $null
    }


    # Get repo Directories
    $RepoBaseDir =  (([DirectoryInfo]::new($PSScriptRoot)).Parent).Parent
    $DistDir     =  [DirectoryInfo]::new((Join-Path -Path $RepoBaseDir.FullName -ChildPath "dist"))
    $BuildDir    =  [DirectoryInfo]::new((Join-Path -Path $RepoBaseDir.FullName -ChildPath "build"))
    $ReleasesDir =  [DirectoryInfo]::new((Join-Path -Path $BuildDir.FullName -ChildPath "release"))
    $SrcDir      =  [DirectoryInfo]::new((Join-Path -Path $RepoBaseDir.FullName -ChildPath "src"))
    

    # Get ModuleInfo
    $_modInfoPath = Join-Path -Path $DistDir.FullName -ChildPath "ModuleInfo.json"
    $ModuleInfo   = Get-Content -Path $_modInfoPath | ConvertFrom-Json


    # Get BuildInfo - create if it doesn't exist
    $_buildInfoPath = Join-Path -Path $BuildDir.FullName -ChildPath "BuildInfo.json"
    if (! (Test-Path $_buildInfoPath)) { New-LrtBuildInfo }
    $BuildInfo = Get-Content $_buildInfoPath | ConvertFrom-Json


    # Update RepoInfo
    $RepoInfo.RepoBaseDir = $RepoBaseDir
    $RepoInfo.DistDir     = $DistDir
    $RepoInfo.BuildDir    = $BuildDir
    $RepoInfo.ReleasesDir = $ReleasesDir
    $RepoInfo.SrcDir      = $SrcDir
    $RepoInfo.ModuleInfo  = $ModuleInfo
    $RepoInfo.BuildInfo   = $BuildInfo


    return $RepoInfo
}