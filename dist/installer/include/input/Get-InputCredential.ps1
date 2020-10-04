using namespace System
Function Get-InputCredential {
    <#
    .SYNOPSIS
        Gets the necessary information to save an API Credential to the configuration directory of
        LogRhythm.Tools.
        Prompts to overwrite if the credential exists.
    .PARAMETER AppId
        The object identifier for an application from Lrt.Config.Input (example: "LogRhythmEcho")
    .PARAMETER AppDescr
        The value of the "Name" field of an application from Lrt.Config.Input (example: "LogRhythm Echo")
    .EXAMPLE
        PS C:\> 
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $AppId,


        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $AppName,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $Username,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNullOrEmpty()]
        [string] $Secret,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch] $SilentInstall
    )

    # LogRhythm.ApiKey.key
    # Load module information
    $InstallerInfo = Get-LrtInstallerInfo
    $ModuleInfo = $InstallerInfo.ModuleInfo
    $LocalAppData = [Environment]::GetFolderPath("LocalApplicationData")

    if ((! ($PSCmdlet.MyInvocation.BoundParameters["SilentInstall"].IsPresent)) -and $Null -eq $Key) {
        Return "Error - SilentInstall provided without providing Key."
    }

    # Configuration directory: config.json & api keys will be stored in Local ApplicationDatas
    $ConfigDirPath = Join-Path `
        -Path $LocalAppData `
        -ChildPath $ModuleInfo.Name


    # Determine the filename and save location for this key
    $KeyFileName = $AppId + ".ApiKey.xml"
    $KeyPath = Join-Path -Path $ConfigDirPath -ChildPath $KeyFileName
    
    # Prompt to Overwrite existing key
    if(Test-Path -Path $KeyPath) {
        if ((! ($PSCmdlet.MyInvocation.BoundParameters["SilentInstall"].IsPresent))) {
            $OverWrite = Confirm-YesNo -Message "  Credential Exists for $KeyFileName, overwrite?" -ForegroundColor Yellow
            if (! $OverWrite) {
                return $null
            }
        }
    }


    # Prompt for Key
    if (! ($PSCmdlet.MyInvocation.BoundParameters["SilentInstall"].IsPresent)) {
        $Key = ""
        while ($Key.Length -lt 10) {
            $Key = Read-Host -AsSecureString -Prompt "  > API Key for $AppName"
            if ($Key.Length -lt 10) {
                # Hint
                Write-Host "    Key less than 10 characters." -ForegroundColor Magenta
            }
        }
    } else {
        $Key = ConvertTo-SecureString -String $Secret -AsPlainText -Force
    }

    # Create credential - with username if provided
    if (! [string]::IsNullOrEmpty($Username)) {
        $_cred = [PSCredential]::new($Username, $Key)
    } else {
        $_cred = [PSCredential]::new($AppId, $Key)
    }

    Export-Clixml -Path $ConfigDirPath\$KeyFileName -InputObject $_cred -force
}