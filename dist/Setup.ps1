using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace System.Security.Principal


<#
.SYNOPSIS
    Install and configure the LogRhythm.Tools PowerShell module.
.DESCRIPTION
    Setup is intended to be run from a published release of LogRhythm.Tools See NOTES
    for details on the expected directory structure.

    There are two main loops of this script:
    1. Prompts for the fields found in Lrt.Config.Input.json
    2. Prompts for credentials found in Lrt.Config.Creds.json
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Setup expects following file structure:

    LogRhythm.Tools.zip:
    ├── install\
    │   ├── input\
    │   │   └── (Get-Input commands)
    │   ├── include\
    │   │   └── (Install commands)
    │   ├── LogRhythm.Tools.zip
    │   ├── LogRhythm.Tools.json
    │   └── Lrt.Installer.psm1
    ├── Setup.ps1
    └── ModuleInfo.json

    <resources>
    <assets>
    <shared>
    <common>
    <packages>
    <content>

    LogRhythm.Tools.zip:
    ├── installer\
    │   ├── packages\
    │   │   └── LogRhythm.Tools.zip
    │   ├── common\
    │   │   └── LogRhythm.Tools.json
    │   │   └── LRLocations.csv
    │   ├── input\
    │   │   └── Get-Input*
    │   │   └── Confirm-*
    │   ├── include\
    │   │   └── (Install commands)
    │   └── Lrt.Installer.psm1
    ├── Setup.ps1
    └── ModuleInfo.json

.LINK
    https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

[CmdletBinding()]
Param( )


#region: Import Commands                                                                           
# Import Lrt.Installer
Get-Module Lrt.Installer | Remove-Module -Force
$LrtInstallerPath = Join-Path -Path $PSScriptRoot -ChildPath "installer"
Import-Module (Join-Path -Path $LrtInstallerPath -ChildPath "Lrt.Installer.psm1") -Force


# Create / Get Configuration Directory
# NOTE: If a configuration file already exists in AppData and there are significant changes in the latest build,
# the installed version should be overwritten.
$ConfigInfo = New-LrtConfig

# Import LogRhythm.Tools.json
$LrtConfig = $ConfigInfo.Config

# Import Previous LogRhythm.Tools config
if ($ConfigInfo.LastConfig) {
    $PreviousLrtConfig = $ConfigInfo.LastConfig | ConvertFrom-Json
}


# Import Setup input configuration
$LrtConfigInput = Get-Content -Path (Join-Path $LrtInstallerPath "config\Lrt.Config.Input.json") -Raw | ConvertFrom-Json


# Import ModuleInfo
$ModuleInfo = Get-Content -Path "$PSScriptRoot\ModuleInfo.json" | ConvertFrom-Json
#endregion


#region: STOP - Banner Time.                                                                       
<##>
$ReleaseTagLength = ($ModuleInfo.ReleaseTag).Length
$s = ""
for ($i = 0; $i -lt $ReleaseTagLength; $i++) {
    $s += "_"
}
Write-Host "888                       8888888b.  888               888    888                       88888888888                888"
Write-Host "888                       888   Y88b 888               888    888                           888                    888"
Write-Host "888                       888    888 888               888    888                           888                    888"
Write-Host "888      .d88b.   .d88b.  888   d88P 88888b.  888  888 888888 88888b.  88888b.d88b.         888   .d88b.   .d88b.  888 .d8888b"
Write-Host "888     d88`"`"88b d88P`"88b 8888888P`"  888 `"88b 888  888 888    888 `"88b 888 `"888 `"88b        888  d88`"`"88b d88`"`"88b 888 88K"
Write-Host "888     888  888 888  888 888 T88b   888  888 888  888 888    888  888 888  888  888        888  888  888 888  888 888 `"Y8888b."
Write-Host "888     Y88..88P Y88b 888 888  T88b  888  888 Y88b 888 Y88b.  888  888 888  888  888 d8b    888  Y88..88P Y88..88P 888      X88"
Write-Host "88888888 `"Y88P`"   `"Y88888 888   T88b 888  888  `"Y88888  `"Y888 888  888 888  888  888 Y8P    888   `"Y88P`"   `"Y88P`"  888  88888P'"
Write-Host "                      888        _______           888        $s"
Write-Host "                 Y8b d88P        " -NoNewline
Write-Host "v $($ModuleInfo.Version)      " -NoNewline -ForegroundColor Cyan
Write-Host "Y8b d88P        " -NoNewline
Write-Host "$($ModuleInfo.ReleaseTag)" -ForegroundColor Magenta
Write-Host "                  `"Y88P`"                       `"Y88P`"`n"
#endregion



#region: Blurb                                                                                     
Write-Host "`nWelcome to LogRhythm.Tools!" -ForegroundColor Green

Write-Host "`nIn the questions that follow, you will be prompted for some basic information about your LogRhythm deployment."
Write-Host "There are also several optional integrations you can enable if you have the necessary licenses or API Keys."
Write-Host "`n* Note *`nIf you already have a configuration file from a previous installation, you can hit [Enter] at any prompt" -ForegroundColor DarkGray
Write-Host "for which you'd like to keep the existing value." -ForegroundColor DarkGray
Write-Host "Configuration Directory: [%LocalAppData%\LogRhythm.Tools\LogRhythm.Tools.json]" -ForegroundColor DarkGray
#endregion



#region: Setup Walkthrough                                                                         
# FallThruValue is the updated value of the previous field, so a value can be re-used without requiring a prompt.
# This satisfies the use case of not having to prompt the user 4 times to set the LogRhythm API URLs.
$FallThruValue = ""


# $ConfigCategory -> Process each top-level config category (General, LogRhythm, etc.)
foreach($ConfigCategory in $LrtConfigInput.PSObject.Properties) {
    Write-Host "`n[ $($ConfigCategory.Value.Name) ]`n=========================================" -ForegroundColor Green

    # Display category message to user
    if ($ConfigCategory.Value.Message) {
        Write-Host $ConfigCategory.Value.Message -ForegroundColor DarkGray
    }
    $ConfigOpt = $true

    #region: Category::Skip Category If Optional                                                               
    # If category is optional, ask user if they want to set it up.
    if ($ConfigCategory.Value.Optional) {
        $ConfigOpt = Confirm-YesNo -Message "Would you like to setup $($ConfigCategory.Value.Name)?"
    }
    # Skip if user chose to skip category
    if (! $ConfigOpt) {
        continue
    }
    #endregion


    #region: Category:: Process Fields Input                                                                
    foreach($ConfigField in $ConfigCategory.Value.Fields.PSObject.Properties) {
        Write-Host "    For guidance enter help or hint as your input value." -ForegroundColor Magenta
        # Input Loop ------------------------------------------------------------------------------
        while (! $ResponseOk) {
            # Exiting Value for this field
            if ($PreviousLrtConfig) {
                $OldValue = $PreviousLrtConfig.($ConfigCategory.Name).($ConfigField.Name)
            } else {
                $OldValue = $LrtConfig.($ConfigCategory.Name).($ConfigField.Name)
            }
            

            # Use previous field's response if this field is marked as FallThru
            if ($ConfigField.Value.FallThru) {
                $Response = $FallThruValue
            # Get / Clean User Input
            } else {
                # $Response = Read-Host -Prompt "  > $($ConfigField.Value.Prompt) [$OldValue]"   #<-- Old value displayed.  Holding off on this.
                $Response = Read-Host -Prompt "  > $($ConfigField.Value.Prompt)"
                $Response = $Response.Trim()
                $Response = Remove-SpecialChars -Value $Response -Allow @("-",".",":")
                Write-Verbose "Response: $Response"
            }
            if (($Response -like "hint") -or ($Response -like 'help')) {
                Write-Host "    Example input: $($ConfigField.Value.Hint)" -ForegroundColor Magenta
                $ResponseOk = $false
                continue
            }

            # Break the loop on this field if no input (keep the same value)
            if ([string]::IsNullOrEmpty($Response)) {
                break
            }

            # > Process Input
            
            Write-Verbose "LrtConfig.$($ConfigCategory.Name).$($ConfigField.Name)"

            # If we are using Get-StringPattern, run that. 
            if ($ConfigField.Value.InputCmd -match "Get-StringPattern") {
                Write-Verbose "Validation: Get-StringPattern"
                Write-Verbose "Old Value: $OldValue"
                $Result = Get-StringPattern `
                    -Value $Response `
                    -OldValue $OldValue `
                    -Pattern $ConfigField.Value.InputPattern.Pattern `
                    -AllowChars $ConfigField.Value.InputPattern.AllowChars
            } else {
                # Otherwise invoke the command requested with common parameters.
                Write-Verbose "Old Value: $OldValue"
                $cmd = $ConfigField.Value.InputCmd +`
                    " -Value `"" + $Response + "`"" + `
                    " -OldValue `"" + $OldValue + "`""
                    Write-Verbose "Validation: $cmd"

                $Result = Invoke-Expression $cmd -Verbose
            }


            # Input OK - Update configuration object
            if ($Result.Valid) {
                Write-Verbose "Previous Value: $($PreviousLrtConfig.($ConfigCategory.Name).($ConfigField.Name))"
                Write-Verbose "New Value: $($Result.Value)"
                $ResponseOk = $true
                $LrtConfig.($ConfigCategory.Name).($ConfigField.Name) = $Result.Value
            # Input BAD - provide hint
            } else {
                Write-Verbose "Validation: `n$Result"
                Write-Host "    hint: [$($ConfigField.Value.Hint)]" -ForegroundColor Magenta
            }
        }
        # End Input Loop --------------------------------------------------------------------------


        # Reset response for next field prompt, set FallThruValue
        $ResponseOk = $false
        $FallThruValue = $Response
    }
    #endregion


    #region: ApiKey Creation                                                                       
    if ($ConfigCategory.Value.HasKey) {

        # Some ApiKeys (oAuth2) will require a Client Id (username)
        if ($ConfigCategory.Value.HasClientId) {

            # Prompt for ClientId if required - no validation other than (length > 2 and < 101)
            $ClientId = Confirm-StringPattern -Message "  > Please enter your Client/App Id" `
                -Pattern "^.{3,100}$" `
                -Hint "Client Id is longer than 2 characters" `
                -AllowChars @("-",".","\")

            # Create credential + username
            $Result = Get-InputCredential `
                -AppId $ConfigCategory.Name `
                -AppName $ConfigCategory.Value.Name `
                -Username $ClientId.Value

        } else {
            # Prompt / create credential without password
            $Result = Get-InputCredential `
                -AppId $ConfigCategory.Name `
                -AppName $ConfigCategory.Value.Name
        }
    }
    #endregion

    #region: Credential Creation                                                                       
    if ($ConfigCategory.Value.HasCredential) {

        # Prompt for Username - no validation other than (length > 2 and < 101)
        $Username = Confirm-StringPattern -Message "  > Please enter your Username" `
            -Pattern "^.*$" `
            -Hint 'Username is any letters, numbers and any of the following: "-",".","\", "@", "_"' `
            -AllowChars @("-",".","\", "@", "_")

        # Make sure Username is not empty, as it otherwise cause error
        if ([string]::IsNullOrEmpty($Username.Value)) {
            $Username.Value = $ConfigCategory.Name
        }

        # Create credential + username
        $Result = Get-InputCredential `
            -AppId $ConfigCategory.Name `
            -AppName $ConfigCategory.Value.Name `
            -Username $Username.Value `
            -UserCredential

    }
    #endregion



    # Write Config
    Write-Verbose "Writing Config to $($ConfigInfo.ConfigFilePath)"
    $LrtConfig | ConvertTo-Json | Set-Content -Path $ConfigInfo.ConfigFilePath -Force
}
#endregion



#region: Install Options                                                                           
# Find Install Archive
$ArchiveFileName = $ModuleInfo.Name + ".zip"
$ArchivePath = "$PSScriptRoot\installer\packages\$ArchiveFileName"
if (! (Test-Path $ArchivePath)) {
    $Err = "Could not locate install archive $ArchivePath. Replace the archive or re-download this release. "
    $Err += "Alternatively, you can install manually using: Install-Lrt -Path <path to archive>"
    throw [FileNotFoundException] $Err
}


# Start Install Options
Write-Host "`n[ Install Options ]`n=========================================" -ForegroundColor Cyan
$ConfirmInstall = Confirm-YesNo -Message "Would you like to install the module now?"
if (! $ConfirmInstall) {
    Write-Host "Not installing. Finished."
    return
}


# Install Scope
$Scopes = @("User","System")
Write-Host "  > You can install this module for the current user (profile) or system-wide (program files)."
$InstallScope = Confirm-Selection -Message "  > Install for user or system?" -Values $Scopes


try {
  Install-Lrt -Path $ArchivePath -Scope $InstallScope.Value
  $Installed = $true
} catch {
    $Installed = $false
    $Err = $PSItem.Exception.Message
    Write-Host "`n  ** Error occurred during installation **" -ForegroundColor Yellow
    Write-Host "  Message: $Err" -ForegroundColor Red
}

if ($Installed) {
    Write-Host "`n<LogRhythm.Tools module successfully installed for scope $($InstallScope.Value).>" -ForegroundColor Green
    Write-Host "`n-----------------------`nTo get started: `n> Import-Module LogRhythm.Tools"
} else {
    Write-Host "  <Setup failed to install LogRhythm.Tools>" -ForegroundColor Yellow
}
#endregion