using namespace System.IO

<#
.SYNOPSIS
    Build and Import the most recent LogRhythm.Tools build in your current
    PowerShell session.
.DESCRIPTION
    New-TestBuild.ps1 script was created as an easy way to build and/or import the
    latest local build of LogRhythm.Tools for the current PowerShell session.

    Generally this is used to aid in the development process, where installing the 
    module under a PSModulePath is cumbersome for continuous testing.

    ----------------------------------------------------------------------------------
    Microsoft Graph Token
    ----------------------------------------------------------------------------------
    (Not Migrated Yet)
    ----------------------------------------------------------------------------------
    Microsoft Defender ATP Token
    ----------------------------------------------------------------------------------
    (Not migrated yet)

.PARAMETER RemoveOld
    Remove previous builds from the build\out directory.
.PARAMETER PassThru
    Will return the BuildInfo object for the build created by New-TestBuild.
    (see Get-LrtBuild for more information)
.INPUTS
    N/A
.OUTPUTS
    If the PassThru switch is set, an object representing the latest build information
    is returned. (see Get-LrtBuild for more information)
.EXAMPLE
    PS C:\> .\New-TestBuild.ps1 -RemoveOld
.NOTES
    The Lrt.Builder module, included in LogRhythm.Tools, is used for
    creating a new module build.  You can also manually build the module
    by importing Lrt.Builder and using its functions.

    For more information on LrtBuilder:
    
    PS > Import-Module .\build\Lrt.Builder.psm1
    PS > Get-Help New-LrtBuild
.LINK
    https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false, Position = 0)]
    [switch] $RemoveOld,

    [Parameter(Mandatory = $false, Position = 2)]
    [switch] $PassThru
)

$StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
# Unload current build
Get-Module LogRhythm.Tools | Remove-Module -Force

#region: Remove Old Builds                                                               
if ($RemoveOld) {
    try {
        Remove-Item -Path $PSScriptRoot\debug\ -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
    } catch {
        Write-Host "Failed to remove old builds in [$PSScriptRoot\debug]" -ForegroundColor Red
        Write-Host "Close any applications which may have an open handle to this directory and try again." -ForegroundColor Yellow

    }
}    
#endregion



#region: BUILD                                                                           
Get-Module Lrt.Builder | Remove-Module -Force
Import-Module $PSScriptRoot\Lrt.Builder.psm1


# Headers
Write-Host "===========================================" -ForegroundColor Gray
Write-Host "> New-TestBuild.ps1 $([datetime]::Now.ToString())"
Write-Host "===========================================" -ForegroundColor Gray


# New Build
Write-Host "Creating new build: " -NoNewline
try {
    $NewBuildPath = New-LrtBuild -ReturnPsm1Path
    Write-Host "[Success]" -ForegroundColor Green
}
catch {
    Write-Host "[Failed]`n" -ForegroundColor Red
    Write-Host "Exception`n---------`n$($PSItem.Exception.Message)" -ForegroundColor Magenta
    return
}


# Import New Build
Write-Host "Import Build:       " -NoNewline
try {
    Import-Module $NewBuildPath
} catch {
    Write-Host "[Failed]`n" -ForegroundColor Red
    Write-Host "Exception`n---------`n$($PSItem.Exception.Message)" -ForegroundColor Magenta
    return
}
Write-Host "[Success]" -ForegroundColor Green
#endregion


# Build Info
$StopWatch.Stop()
Write-Host "`n<Completed in $($StopWatch.Elapsed.TotalMilliseconds) ms>" -ForegroundColor DarkGray

if ($PassThru) {
    return Get-LrtBuild
}