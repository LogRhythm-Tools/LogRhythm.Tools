using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrtBuildInfo {
    <#
    .SYNOPSIS
        Create a new BuildInfo file.
    .DESCRIPTION
        The New-LrtBuildInfo cmdlet creates an empty BuildInfo.json file in the build directory.
    .PARAMETER Force
        Creates a new BuildInfo file, even if one already exists.
    .INPUTS
        None
    .OUTPUTS
        None
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false)]
        [switch] $Force
    )

    # Get Build Paths
    $ModuleBase = (([DirectoryInfo]::new($PSScriptRoot)).Parent).Parent
    $BuildPath = Join-Path $ModuleBase.FullName "build"
    $BuildInfoPath = Join-Path $BuildPath "BuildInfo.json"

    # Setup BuildInfo
    $BuildInfo = [PSCustomObject]@{
        Version      = "1.0.0"
        Guid         = "00000000-0000-0000-0000-000000000000"
        BuildTime    = "2000-01-01 01:01:00Z"
        Path         = "c:\"
        Psm1Path     = "c:\"
        ReleaseTag = "none"
    }

    # If [Force] parameter is set, create a new BuildInfo file.
    if ($Force) {
        if (Test-Path $BuildPath) {
            $BuildInfo | ConvertTo-Json | Out-File $BuildInfoPath
            return $null
        } else {
            throw [DirectoryNotFoundException] "[New-LrtBuildInfo]: Unable to find build directory $BuildPath"
        }
    }

    # If we don't have an existing BuildInfo file, and the
    # build path exists, create a new blank BuildInfo file.
    if (! (Test-Path $BuildInfoPath)) {
        if (Test-Path $BuildPath) {
            $BuildInfo | ConvertTo-Json | Out-File $BuildInfoPath
        } else {
            throw [DirectoryNotFoundException] "[New-LrtBuildInfo]: Unable to find build directory $BuildPath"
        }
    } else {
        Write-Host "[New-LrtBuildInfo]: BuildInfo.json file already exists, will not overwrite."
    }
}