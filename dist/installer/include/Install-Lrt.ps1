using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace System.Security.Principal

function Install-Lrt {
    <#
    .SYNOPSIS
        Installs the Lrt module in either the system or user PowerShell Modules directory.
    .DESCRIPTION
        > Determine the proper install path based on the Scope (User|System)
        > Create directories as needed (User only)
        > Add to PSModulePath if needed
        ? Check for previous version
        > Extract to install path
    .PARAMETER Path
        Path to the archive that contains the module source files and psm1.
        In most use cases the archive will be under the install folder.
    .PARAMETER Scope
        User:   c:\Users\<user>\Documents\WindowsPowerShell\Modules\
        System: c:\Program Files\WindowsPowerShell\Modules\
    .INPUTS
        None
    .OUTPUTS
        None
    .EXAMPLE
        Install-Lrt -Scope User
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [FileInfo] $Path,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('User','System')]
        [string] $Scope = "User"
    )

    
    #region Scope: Check for Admin (System Scope)                                                  
    # Possible Cleanup: We do pretty much the same thing twice - unify
    if ($Scope -eq "System") {
        Write-Verbose "Installing with scope: System"
        
        # Check admin privileges
        if (! (([WindowsPrincipal][WindowsIdentity]::GetCurrent()).IsInRole([WindowsBuiltInRole]::Administrator))) {
            throw [Exception] "Setup needs to be run with Administrator privileges to install to system."
        }
    }
    #endregion



    #region: Setup & Validation                                                                    
    
    $InstallerInfo = Get-LrtInstallerInfo
    $ModuleInfo = $InstallerInfo.ModuleInfo
    # Collection of paths currently in PSModulePath
    $ModulePaths = $env:PSModulePath.Split(';')

    # By default it should be located in .\installer\packages\
    if (! $Path) {
        $BaseDir = (([DirectoryInfo]::new($PSScriptRoot)).Parent).Parent
        $ArchivePath = Join-Path -Path $BaseDir.FullName -ChildPath "installer\packages" | 
            Join-Path -ChildPath $ModuleInfo.ArchiveFileName
        $Path = [FileInfo]::new($ArchivePath)
    }

    if (! $Path.Exists) {
        throw [ArgumentException] "[Install-Lrt]: Failed to locate install archive $($Path.FullName)."
    }
    #endregion



    #region: Validate Module base install directory                                                
    $ScopeInfo = $InstallerInfo.InstallScopes.($Scope)

    # Validate the Modules installation directory for User/System
    if (! (Test-Path -Path $ScopeInfo.Path)) {
        if ($Scope -eq "User") {
            # Ok to create missing Modules directory for [User] scope
            $_created = New-Item -Path $Env:HOME -Name "WindowsPowerShell\Modules" `
                -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
            Write-Verbose "Created directory [$($_created.FullName)]"
        }
        if ($Scope -eq "System") {
            # Fail for [System Scope]
            throw [Exception] "[Install-Lrt]: $Scope module directory [$($ScopeInfo.Path)] is missing, cannot proceed."
        }
    }


    # Add to PSModulePath if needed
    if (! ($ModulePaths.Contains(($ScopeInfo.Path)))) {
        Write-Verbose "$Scope modules directory not in module path. Adding."
        $p = [Environment]::GetEnvironmentVariable("PSModulePath")
        $p += ";$($ScopeInfo.Path)"
        [Environment]::SetEnvironmentVariable("PSModulePath",$p)
    }

    $InstallPath # = Join-Path -Path $ScopeInfo.Path -ChildPath $ModuleInfo.Name

    # If we didn't end up with an InstallPath for some reason, fail
    if ([string]::IsNullOrEmpty($ScopeInfo.InstallPath)) {
        throw [Exception] "[Install-Lrt]: Unable to determine module install location for $Scope."
    }
    #endregion



    #region: Action: Uninstall / Install                                                 
    # Get current install state
    

    # Various sanity checks in case the module is already installed.
    if ($ScopeInfo.Installed) {
        $InstallerVersion = $ModuleInfo.Version

        # If there's only one installed version, that version will be $NewestVersion
        $NewestVersion = $ScopeInfo.Versions
        # If there are more than one, we need to sort and select the first item in list
        if ($ScopeInfo.Versions.Count -gt 1) {
            $NewestVersion =  ($ScopeInfo.Versions | Sort-Object -Descending)[0]    
        }
        
        Write-Host "Installer Version: $InstallerVersion"
        Write-Host "Newest Version: $NewestVersion"

        # Higher version detected
        if ($NewestVersion -gt $InstallerVersion) {
            Write-Host "`n    Warning: Currently installed version is ($($NewestVersion)) " -NoNewline -ForegroundColor Yellow
            Write-Host "is greater than installer version ($($InstallerVersion))" -ForegroundColor Yellow
            $Continue = Confirm-YesNo -Message "    Proceed?" -ForegroundColor Yellow
            if (! $Continue) {
                Write-Host "Aborting installation." -ForegroundColor Red
                return $false
            }
        }


        # If there is an installed version that matches this version, remove it.
        if ($ScopeInfo.Versions.Contains($InstallerVersion)) {
            $_remove = Join-Path -Path $ScopeInfo.InstallPath -ChildPath $InstallerVersion
            try {
                Remove-Item -Path $_remove -Recurse -Force
            }
            catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }

        
        # Retain previously installed versions by moving them to Temp
        $MoveDirs = Get-ChildItem -Path $ScopeInfo.InstallPath -Directory
        $ReturnDirs = $MoveDirs | ForEach-Object { Move-Item -Path $_.FullName -Destination $env:temp -PassThru }
        # Remove the base module folder
        Remove-Item -Path $ScopeInfo.InstallPAth -Recurse -Force
    }


    # Perform install
    Write-Verbose "Installing to $($ScopeInfo.InstallPath)"
    try { Expand-Archive -Path $Path.FullName -DestinationPath $ScopeInfo.InstallPath }
    catch { $PSCmdlet.ThrowTerminatingError($PSItem) }

    
    # Move dirs back if we have any
    if ($ReturnDirs) {
        $ReturnDirs | ForEach-Object { Move-Item -Path $_.FullName -Destination $ScopeInfo.InstallPath }    
    }
    

    return $true
    #endregion
}