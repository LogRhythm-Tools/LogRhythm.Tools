using namespace System
using namespace System.IO
using namespace System.Collections.Generic
function New-LrtBuild {
<#
    .SYNOPSIS
        Create a new build for the LogRhythm.Tools module.
    .DESCRIPTION
        The New-LrtBuild cmdlet creates a new build for the LogRhythm.Tools
        module, based on the information stored in ModuleInfo.json and parameters provided
        to this cmdlet.

        Overview of the actions taken by the New-LrtBuild cmdlet:

          - A unique id (guid) is assigned to the new build which will be used in the
            module's manifest file and by other LrtBuilder cmdlets to identify this build.

          - The build guid is used to create a unique directory under build\out. All relevant
            module files and cmdlets will be copied here, including a dynamically generated 
            module manifest file based on ModuleInfo.json and parameters provided to New-LrtBuild.

          - If the <Version> parameter is not provided, the value in ModuleInfo.json is used.

          - Information about the new build is written to build/BuildInfo.json

          - A properly structured archive of the build will be created in the build directory,
            ready to be extracted directly into a PowerShell Module directory, e.g.
            "C:\Program Files\WindowsPowerShell\Modules"
    .PARAMETER Version
        An optional parameter which specifies the version number to use for the module. 
        Values are expected to match the convention: "x.y.z". 
        
        If omitted, the version from ModuleInfo.json will be used instead. The Version number 
        is used for directory naming, as well as the module's new manifest file (psd1).
    .PARAMETER ReleaseTag
        A comment to be added to the module's manifest file. This can be used to identify any
        key features or bug fixes. This also helps to distinguish between multiple builds.
        If ommitted, this is left blank.
    .PARAMETER ReturnPsm1Path
        Instead of returning the BuildId, return the path to the Psm1 file created by this
        cmdlet.
    .INPUTS
        This cmdlet does not accept pipeline input.
    .OUTPUTS
        System.Guid
        The guid assigned to this build
    .EXAMPLE
        PS C:\> New-LrtBuild  -Version 1.0.1

        DESCRIPTION
        -----------
        Create a new build of this module as Version 1.0.1, without a release note.
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Version = "0.0.0",

        [Parameter(Mandatory=$false,Position=1)]
        [string] $ReleaseTag = "",

        [Parameter(Mandatory=$false, Position=2)]
        [switch] $ReturnPsm1Path
    )


    # Pattern to match required version format
    $VersionMatch = [regex]::new("^\d\.\d\.\d")
    if (-not ($Version -match $VersionMatch)) {
        throw [exception] "Invalid Version ($Version). Expected Format: x.y.z"
    }




    #region: Directories and Paths                                                   
    Write-Verbose "[New-LrtBuild]: Starting Build"
    $Target = "debug"
    
    # Prep Build Directories
    $BuildId = [Guid]::NewGuid()

    # Paths
    $RepoInfo = Get-LrtRepoInfo
    $BuildPath = $RepoInfo.BuildDir.FullName
    $SrcPath = $RepoInfo.SrcDir.FullName

    # Module Info
    $ModuleInfo = $RepoInfo.ModuleInfo
    $ModuleInfoPath = Join-Path -Path $RepoInfo.DistDir.FullName -ChildPath "ModuleInfo.json"
    # Build Info
    $BuildInfo = $RepoInfo.BuildInfo
    $BuildInfoPath = Join-Path -Path $BuildPath -ChildPath "BuildInfo.json"

    # Create build container directory
    $BuildContainerDir = New-Item -Path (Join-Path $BuildPath $Target) -Name $BuildId -ItemType "directory"
    $BuildContainerPath = $BuildContainerDir.FullName


    # Create version directory (debug\guid\version)
    if ($Version.Equals("0.0.0")) {
        $Version = $ModuleInfo.Version
    }
    $BuildSrcDir = New-Item -Path $BuildContainerDir.FullName -Name $Version -ItemType "directory"
    $BuildSrcPath = $BuildSrcDir.FullName
    $BuildPsd1Path = Join-Path $BuildSrcPath $ModuleInfo.Psd1
    $BuildPsm1Path = Join-Path $BuildSrcPath $ModuleInfo.Psm1
    #endregion



    #region: Copy Source To Build                                                    
    Write-Verbose "[New-LrtBuild]: Copying files..."
    # Copy Source Directories
    Copy-Item $SrcPath\Public -Destination $BuildSrcPath -Recurse
    Copy-Item $SrcPath\Private -Destination $BuildSrcPath -Recurse

    Copy-Item (Join-Path $SrcPath $ModuleInfo.Ps1xml) -Destination $BuildSrcPath
    Copy-Item (Join-Path $SrcPath $ModuleInfo.Psm1) -Destination $BuildSrcPath
    
    $RequiredModules = $ModuleInfo.RequiredModules

    # Process any extra files to be included with the module.
    foreach ($item in $ModuleInfo.Assemblies) {
        $itemSrcPath = Join-Path $SrcPath $item
        if (Test-Path $itemSrcPath) {
            Copy-Item $itemSrcPath -Destination $BuildSrcPath
        } else {
            Write-Host "WARNING: Failed to copy item $item to build destination." -ForegroundColor Yellow
            Write-Host "  Source:      $itemSrcPath" -ForegroundColor DarkGray
            Write-Host "  Destination: $BuildSrcPath\$item" -ForegroundColor DarkGray
        }
    }
    #endregion



    #region: Create Manifest                                                         
    # If no release tag is specified, use the existing one
    if ([string]::IsNullOrEmpty($ReleaseTag)) {
        $ReleaseTag = $ModuleInfo.ReleaseTag
    }
    
    # Create Manifest
    New-ModuleManifest -Path $BuildPsd1Path `
        -RootModule $ModuleInfo.Psm1 `
        -Guid $BuildId `
        -Author $ModuleInfo.Author `
        -CompanyName $ModuleInfo.CompanyName `
        -Copyright $ModuleInfo.Copyright `
        -ModuleVersion $Version `
        -Description $ModuleInfo.Description `
        -PowerShellVersion $ModuleInfo.PowerShellVersion `
        -RequiredModules $RequiredModules `
        -Tags $ModuleInfo.Tags `
        -ProjectUri $ModuleInfo.ProjectUri `
        -FormatsToProcess $ModuleInfo.Ps1xml `
        -ReleaseNotes $ReleaseTag `
        -RequiredAssemblies $ModuleInfo.Assemblies
    #endregion



    #region: Archive and Update                                                      
    Write-Verbose "[New-LrtBuild]: Creating build archive..."
    # Compress Module for distribution
    $BuildSrcDir | Compress-Archive -DestinationPath (Join-Path $BuildContainerPath $ModuleInfo.ArchiveFileName)

    # Update Test Config
    $BuildInfo.Version = $Version
    $BuildInfo.Guid = $BuildId
    $BuildInfo.BuildTime = [datetime]::now.ToString('u')
    $BuildInfo.Path = $BuildContainerDir.FullName
    $BuildInfo.Psm1Path = $BuildPsm1Path
    $BuildInfo.ReleaseTag = $ReleaseTag
    $BuildInfo | ConvertTo-Json | Out-File $BuildInfoPath
    #endregion



    #region: Update ModuleInfo.json                                                      
    $ModuleInfo.Version = $Version
    $ModuleInfo.ReleaseTag = $ReleaseTag
    $ModuleInfo | ConvertTo-Json | Out-File $ModuleInfoPath
    #endregion


    Write-Verbose "[New-LrtBuild]: Complete! $BuildId"
    if ($ReturnPsm1Path) {
        return $BuildPsm1Path
    }
    return $BuildId
}