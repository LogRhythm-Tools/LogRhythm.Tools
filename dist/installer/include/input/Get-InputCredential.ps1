using namespace System
Function Get-InputCredential {
    <#
    .SYNOPSIS
        Gets the necessary information to save an API Credential to the configuration directory of
        LogRhythm.Tools.
        Prompts to overwrite if the credential exists.
    .PARAMETER AppId
        The object identifier for an application from Lrt.Config.Input (example: "LogRhythmEcho")
    .PARAMETER AppName
        The value of the "Name" field of an application from Lrt.Config.Input (example: "LogRhythm Echo")
    .PARAMETER Username
        The value of the "Username" part of the credential object
    .PARAMETER UserCredential
        Switch from asking for an API Key to ask for a User PassewThe value of the "Username" part of the credential object
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
        [switch] $UserCredential = $false
    )

    # LogRhythm.ApiKey.key
    # Load module information
    $InstallerInfo = Get-LrtInstallerInfo
    $ModuleInfo = $InstallerInfo.ModuleInfo
    $LocalAppData = [Environment]::GetFolderPath("LocalApplicationData")


    # Configuration directory: config.json & api keys will be stored in Local ApplicationDatas
    $ConfigDirPath = Join-Path `
        -Path $LocalAppData `
        -ChildPath $ModuleInfo.Name


    # Determine the filename and save location for this key
    if ($UserCredential) {
        $KeyFileName = $AppId + ".Credential.xml"
    }
    else
    {
        $KeyFileName = $AppId + ".ApiKey.xml"
    }
    $KeyPath = Join-Path -Path $ConfigDirPath -ChildPath $KeyFileName
    
    # Prompt to Overwrite existing key
    if(Test-Path -Path $KeyPath) {
        $OverWrite = Confirm-YesNo -Message "  Credential Exists for $KeyFileName, overwrite?" -ForegroundColor Yellow
        if (! $OverWrite) {
            return $null
        }
    }


    # Prompt for Key / Password
    $Key = ""
    if ($UserCredential) {
            $Key = Read-Host -AsSecureString -Prompt "  > Password for $AppName"
    }
    else
    {
        while ($Key.Length -lt 10) {
            $Key = Read-Host -AsSecureString -Prompt "  > API Key for $AppName"
            if ($Key.Length -lt 10) {
                # Hint
                Write-Host "    Key less than 10 characters." -ForegroundColor Magenta
            }
        }
    }
    
    # Create credential - with username if provided
    if (! [string]::IsNullOrEmpty($Username)) {
        $_cred = [PSCredential]::new($Username, $Key)
    } else {
        $_cred = [PSCredential]::new($AppId, $Key)
    }
    
    Export-Clixml -Path $ConfigDirPath\$KeyFileName -InputObject $_cred
}