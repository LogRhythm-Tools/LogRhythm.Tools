using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrtBuild {
    <#
    .SYNOPSIS
        Gets information about a build created by LrtBuilder.
    .DESCRIPTION
        Gets information about a build created by LrtBuilder, or information 
        about the currently installed LogRhythm.Tools module in 
        C:\Program Files\WindowsPowerShell\Modules\
    .PARAMETER BuildId
        Get Build information for the specified build guid as [string]
    .PARAMETER Guid
        Get Build information for the specified [guid]
    .PARAMETER Installed
        Get build information for the currently installed module for this project.
    .INPUTS
        You can pipe a string or guid representing the BuildId to this cmdlet to 
        find information about that specific build.
    .OUTPUTS
        PSCustomObject:
            BuildId     [string]
            Directory   [DirectoryInfo]
            Path        [string]
            Install     [FileInfo]
            Module      [FileInfo]
    .EXAMPLE
        Get-LrtBuild "d7fd1b45-5cba-4bb5-8d12-05620b7e0689"
        Get-LrtBuild ([System.Guid]::Parse("d7fd1b45-5cba-4bb5-8d12-05620b7e0689"))
        Get-LrtBuild -Installed
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [string] $BuildId,

        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [guid] $Guid,

        [Parameter(Mandatory=$false)]
        [switch] $Installed
    )

    Begin { }

    Process {
        # Normalize Guid
        $Key = $BuildId
        if ($PSBoundParameters.ContainsKey("Guid")) {
            $Key = $Guid.ToString()
        }


        # Build Paths & Info
        $InstallPath = "C:\Program Files\WindowsPowerShell\Modules\"
        $RepoInfo = Get-LrtRepoInfo
        $BuildPath = $RepoInfo.BuildDir.FullName
        $BuildInfoPath = Join-Path $BuildPath "BuildInfo.json"
        
        # Get ModuleInfo
        $ModuleInfo = $RepoInfo.ModuleInfo

        if (! (Test-Path $BuildInfoPath)) {
            New-LrtBuildInfo
            Write-Verbose "[Get-LrtBuild]: Created new BuildInfo file at $BuildInfoPath"
        }
        $BuildInfo = Get-Content $BuildInfoPath -Raw | ConvertFrom-Json
        
        
        # Result Object structure
        $Build = [PSCustomObject]@{
            Guid       = $null
            Name       = $null
            Path       = $null
            Archive    = $null
            Psm1Path   = $null
            Version    = $null
        }


        # Option 1) Get the currently installed version of the module.
        if ($Installed) {
            if (Test-Path -Path (Join-Path  $InstallPath $ModuleInfo.Name) -PathType Container) {
                # If some version already imported, remove it so we can specifically get the installed version.
                Get-Module $ModuleInfo.Name | Remove-Module -Force
                
                Import-Module $ModuleInfo.Name
                $Info = Get-Module $ModuleInfo.Name

                $Build.Guid = [guid]::Parse($Info.Guid)
                $Build.Name = $ModuleInfo.Name
                $Build.Path = ([DirectoryInfo]::new($Info.ModuleBase)).Parent
                $Build.Archive = $null
                $Build.Psm1Path  = [FileInfo]::new($Info.Path)
                $Build.Version = $Info.Version

                return $Build
            } else {
                # throw [Exception] "Module not currently installed."
                
                return $null
            }
        }


        # Option 2)  Get the latest build if guid not specified
        if (! $Key) {
            if ([string]::IsNullOrEmpty($BuildInfo.Psm1Path)) {
                Write-Verbose "[Get-LrtBuild]: BuildInfo does not contain a valid build."
            } else {
                $Build.Guid = [guid]::Parse($BuildInfo.Guid)
                $Build.Name = $ModuleInfo.Name
                $Build.Path = [DirectoryInfo]::new($BuildInfo.Path)
                $Build.Archive = [FileInfo]::new($(Join-Path $Build.Path "$($Build.Name).zip"))
                $Build.Psm1Path  = [FileInfo]::new($BuildInfo.Psm1Path)
                $Build.Version = $BuildInfo.Version

                return $Build
            }
        }


        # Option 3) Attempt to find the requested build.
        $Builds = @(Get-ChildItem -Path $BuildPath\debug\ -Directory -ErrorAction SilentlyContinue)
        foreach ($b in $Builds) {
            if ($b.Name.Equals($Key)) {
                $Build.Guid = $Key
                $Build.Name = $ModuleInfo.Name
                $Build.Path = $b
                $Build.Archive = [FileInfo]::new($(Join-Path $Build.Path.FullName "$($Build.Name).zip"))
                $Build.Psm1Path  = $b | Get-ChildItem -Filter *.psm1 -Recurse
                $Build.Version = $Build.Psm1Path.Directory.BaseName

                return $Build
            }
        }


        # Option 4) RETURN NULL
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            $build_list = Get-ChildItem (Join-Path $BuildPath "debug")
            $build_list | Format-List
        }
        # throw [Exception] "Unable to find $Key in builds directory."
        Write-Verbose "[Get-LrtBuild]: Unable to find $Key in builds directory."
        return $null
    }


    End { }
}