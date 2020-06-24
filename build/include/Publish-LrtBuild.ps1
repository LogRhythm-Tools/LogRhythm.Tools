using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Publish-LrtBuild {
    <#
    .SYNOPSIS
        Publish a LogRhythm.Tools build.
    .DESCRIPTION
        Publish-LrtBuild will prepare a build created by the New-LrtBuild cmdlet to be
        published for distribution.
        
        All of the files necessary for installing the release will be copied to a
        new directory which is then compressed and ready for general distribution.

        By default, the release will be saved to your desktop unless a destination
        parameter is provided.
    .PARAMETER BuildId
        The BuildId (guid) of the build to publish.
    .PARAMETER Destination
        (Optional) Specifies the directory to which the release archive is saved.
        If ommited, the release will be saved to the desktop.
    .PARAMETER PassThru
        (Optional) If provided, the resulting release archive is returned as 
        a [FileInfo] object.
    .INPUTS
        [Guid]  => BuildId
    .OUTPUTS
        If the PassThru switch is used, the resulting release archive is returned 
        as a [FileInfo] object.

        The name of the compressed release is determined by (module name)+(version)
        resulting in: LogRhythm.Tools-x.y.z.zip
    .EXAMPLE
        C:\ PS> Publish-LrtBuild -BuildId "ec7ff2a7-a329-4ef9-af0b-af39b4ba0e91"

        Explanation:

        Gets the build associated with guid ec7ff2a7-a329-4ef9-af0b-af39b4ba0e91 and
        publishes to your desktop.
    .EXAMPLE
        C:\ PS> New-LrtBuild -Version 0.9.9 | Publish-LrtBuild -PassThru -Destination "C:\tmp\"
        
        Explanation:

        Creates a new build tagged 0.9.9 + publishes to C:\tmp\LogRhythm.Tools-0.9.9.zip
        and returns the created archive as a [FileInfo] object.
    .NOTES
        [Background]
        
        BuildId is the guid assigned when Lrt is built by the LrtBuilder module. Builds
        it creates are stored under ~/build/out/ and are created within folders named for
        their repsective BuildId (guid) as the name.
        
        For more information on the build process:
        > Get-Help New-LrtBuild
  
        [Release]

        The Publish-LrtBuild cmdlet will package the build described
        above as follows:

        + Create ReleaseBuild Directory [~/build/release/BuildId]
        - Copy to ReleaseBuild/
            ~/Setup.psm
            ~/ModuleInfo.json
            ~/install/

        - Copy to ReleaseBuild/install/
            ~/build/out/BuildId/LogRhythm.Tools.zip
            ~/src/include/LogRhythm.Tools.json

    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    # ===================================================================
    # Reference: [Build] object returned from Get-LrtBuild
        # Guid     : ec7ff2a7-a329-4ef9-af0b-af39b4ba0e91
        # Name     : LogRhythm.Tools
        # Path     : ec7ff2a7-a329-4ef9-af0b-af39b4ba0e91
        # Archive  : C:\repos\_community\SmartResponse.Framework\build\...
        # Psm1Path : LogRhythm.Tools.psm1
        # Version  : 0.9.8
    # ===================================================================

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [guid] $BuildId,

        [Parameter(Mandatory = $false, Position = 1)]
        [DirectoryInfo] $Destination,

        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru
    )

    #region: Directories & Paths                                                         
    # Get repo Directories
    $RepoInfo = Get-LrtRepoInfo
    $ReleasesDir = $RepoInfo.ReleasesDir
    $DistDir = $RepoInfo.DistDir
    $ModuleInfo = $RepoInfo.ModuleInfo



    # Get information about the requested build
    $Build = Get-LrtBuild $BuildId
    if (! $Build) {
        throw [ArgumentException] "BuildId $BuildId not found."
    }


    # Release Filename
    $ReleaseZip = $ModuleInfo.Name + "-" + $ModuleInfo.Version + ".zip"

    # Set / Validate release destination
    if ($Destination) {
        if (! $Destination.Exists) {
            throw [ArgumentException] "Destination directory $($Destination.FullName) does not exist."
        }
    } else {
        # If Destination isn't provided, save the release to the desktop
        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        $Destination = [DirectoryInfo]::new($DesktopPath)
    }
    
    # Full path to the release zip
    $PubZipFilePath = Join-Path -Path $Destination.FullName -ChildPath $ReleaseZip
    #endregion



    #region Create Release Directory                                                 
    # Make a directory to contain the release - .\reporoot\build\release\BuildId\
    $ReleaseBuildDir = [DirectoryInfo]::new((Join-Path -Path $ReleasesDir.FullName -ChildPath $Build.Guid))
    # If release directory for build already exists, remove it.
    if ($ReleaseBuildDir.Exists) {
        Write-Verbose "Release dir for $BuildId exists. Attempting to remove."
        try {
            Remove-Item -Path $ReleaseBuildDir.FullName -Recurse
            Write-Verbose "Release $BuildId : Removed OK"
        } catch {
            Write-Host "[Publish]: Could not remove existing release dir." -ForegroundColor Yellow
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
    # Create release directory for build
    try {
        $ReleaseBuildDir = New-Item -Path $ReleasesDir.FullName -Name $Build.Guid -ItemType "directory"
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
    Write-Verbose "Release directory created:  $($ReleaseBuildDir.FullName)"
    #endregion



    #region: Copy Release Files                                                      
    # Copy: [dist]*
    Write-Verbose "Copy [dist] to ReleaseBuildDir"
    $DistContents = Join-Path -Path $DistDir.FullName -ChildPath "*"
    Copy-Item -Path $DistContents -Destination $ReleaseBuildDir.FullName -Recurse


    # Copy: module build zip
    Write-Verbose "Copy module build $BuildId to ReleaseBuildDir "
    Copy-Item -Path $Build.Archive -Destination (Join-Path -Path $ReleaseBuildDir.FullName -ChildPath "installer\packages")
    #endregion



        #region: Create Release Archive                                                              
    Write-Verbose "Create release archive in $($Destination.FullName)"
    
    # To omit the build id from compression, we need to add * to the end of $Destination
    $CompressTarget = Join-Path -Path $ReleaseBuildDir.FullName -ChildPath "*"


    try {
        Compress-Archive -Path $CompressTarget -DestinationPath $PubZipFilePath -Force
        $ReleaseFileInfo = [DirectoryInfo]::new($PubZipFilePath)
    } catch {
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }

    Write-Verbose "Release archive successfully created: $($Destination.FullName)$ReleaseZip"

    # Return [FileInfo] of archive if requested
    if ($PassThru) {
        return $ReleaseFileInfo
    }    
    #endregion
}