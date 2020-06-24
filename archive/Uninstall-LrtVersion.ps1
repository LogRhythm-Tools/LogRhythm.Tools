using namespace System
using namespace System.IO
using namespace System.Security.Principal
using namespace System.Management.Automation

function Uninstall-LrtVersion {
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
#TODO: Remove this probably...

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [string] $Version
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


}
