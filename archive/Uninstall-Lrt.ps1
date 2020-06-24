using namespace System
using namespace System.IO
using namespace System.Security.Principal
using namespace System.Management.Automation

function UnInstall-Lrt {
<#
    .SYNOPSIS
        Uninstalls the module.
    .DESCRIPTION
        The UnInstall-Lrt cmdlet uninstalls the Lrt module from the local computer.
        By default the installation directory is C:\Program Files\WindowsPowerShell\Modules\

        When unauthorized access errors are thrown, close all PowerShell and IDE windows and re-run this cmdlet.
    .PARAMETER InstallPath
        Path to the directory of the Lrt module, e.g. c:\users\bob\Documents\WindowsPowerShell\Modules\Lrt\
    .INPUTS
        [DirectoryInfo] => InstallPAth
    .OUTPUTS
        None
        Throws exception if the installation path is not found.
    .EXAMPLE
        PS C:\> UnInstall-Lrt -InstallPath "c:\users\bob\Documents\WindowsPowerShell\Modules\Lrt\"
        ---
        Description: Will remove the module from the local computer.
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ParameterSetName = 'Path',
            Position = 0
        )]
        [DirectoryInfo] $InstallPath,

        [Parameter(
            Mandatory = $false,
            ParameterSetName = 'Scope',
            Position = 1
        )]
        [ValidateSet('User','System')]
        [string] $Scope
    )

    #region: Path Setup                                                                  
    $InstallerInfo = Get-LrtInstallerInfo
    $ModuleInfo = $InstallerInfo.ModuleInfo
    # USER SCOPE
    # C:\Users\USERNAME\Documents\WindowsPowerShell\Modules
    $UserDir = Get-LrtInstallPath -Scope User
    # C:\Users\USERNAME\Documents\WindowsPowerShell\Modules\LogRhythm.Tools
    $UserInstallPath = Join-Path -Path $UserDir -ChildPath $ModuleInfo.Name
    $UserInstallDir = [DirectoryInfo]::new($UserInstallPath)    


    # SYSTEM SCOPE
    # C:\Program Files\WindowsPowerShell\Modules
    $SystemDir = Get-LrtInstallPath -Scope System
    # C:\Program Files\WindowsPowerShell\Modules\LogRhythm.Tools
    $SystemInstallPath = Join-Path -Path $SystemDir -ChildPath $ModuleInfo.Name
    $SystemInstallDir = [DirectoryInfo]::new($SystemInstallPath)
    #endregion



    #region: Get Locations                                                               
    # I think this might be overkill, but I'm making this flexible because I don't know
    # what future use cases might be.  This command can be called pretty blindly and it
    # should work.
    
    # A list of locations to remove from.
    $Installs = [List[string]]::new()


    # InstallPath Option
    if ($InstallPath) {
        if ($InstallPath.Exists) {
            $Installs.Add($InstallPath)
        } else {
            throw [ArgumentException] "Provided install path $InstallPath does not exist."
        }
    }

    # Scope Option - Figure out which scope was requested and make sure it exists
    if (! ([string]::IsNullOrEmpty($Scope))) {
        # Scope: System
        if ($Scope -eq "System") {
            if (! $SystemInstallDir.Exists) {
                throw [ArgumentException] "No install found in $($SystemInstallDir.FullName)"
            }
            $Installs.Add($SystemInstallDir.FullName)
        }
        # Scope: User
        if ($Scope -eq "User") {
            if (! $UserInstallDir.Exists) {
                throw [ArgumentException] "No install found in $($UserInstallDir.FullName)"
            }
            $Installs.Add($UserInstallDir.FullName)
        }
    }

    # No scope / No path - try to remove system & user if they exist
    if ((! $InstallPath) -and ([string]::IsNullOrEmpty($Scope))) {
        # Scope: System
        if ($SystemInstallDir.Exists) {
            $Installs.Add($SystemInstallDir.FullName)    
        }
        # Scope: User
        if ($UserInstallDir.Exists) {
            $Installs.Add($UserInstallDir.FullName)    
        }
    }
    #endregion


    if ($Installs.Count -eq 0) {
        Write-Host "[Uninstall-Lrt]: Nothing to remove."
        return
    }

    foreach ($install in $Installs) {
        if ($install -eq $SystemInstallPath) {
            if ($InstallPath.FullName -eq $SystemInstallPath) {
                $CurrentUser = New-Object Security.Principal.WindowsPrincipal([WindowsIdentity]::GetCurrent())
                $IsAdmin = $CurrentUser.IsInRole([WindowsBuiltInRole]::Administrator)
                if (-not $IsAdmin) {
                    throw [Exception] "To remove Lrt from the system install path, run the command with administrator rights."
                }
            }
        }
    }

    # Check if Administrator - System Install Path only


    #region: Remove Installation Files                                                   
    # Get all files recursively
    $RemoveItems =  @(Get-ChildItem -Recurse -Path $InstallPath) | 
        Select-Object -ExpandProperty FullName | Sort-Object -Descending

    foreach ($item in $RemoveItems) {
        try {
            Write-Verbose "Removing Item $item"
            Remove-Item -Path $item -Force -ErrorAction Stop
        }
        catch {
            Write-Host "`nLocked File: " -ForegroundColor Yellow -NoNewline
            Write-Host "$item`n" -ForegroundColor Cyan
            Write-Host "This is likely due to a loaded assembly (dll) which cannot be dynamically unloaded." -ForegroundColor Blue
            Write-Host "Close all PowerShell and IDE windows, then try again.`nError Details:" -ForegroundColor Blue
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }

    # Catch-all + Directory
    try {
        Remove-Item $InstallPath -Force -Recurse
    }
    catch {
        Write-Host "`nFailed to remove directory $InstallPath" -ForegroundColor Blue
        Write-Host "Close all PowerShell and IDE windows, then try again.`nError Details:" -ForegroundColor Blue
        $PSCmdlet.ThrowTerminatingError($PSItem)
    }
    #endregion


}
