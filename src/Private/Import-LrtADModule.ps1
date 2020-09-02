Function Import-LrtADModule {
    <#
    .SYNOPSIS
        Attempts to load ActiveDirectory module.
    .INPUTS
        None
    .OUTPUTS
        [bool] is module is loaded
    .EXAMPLE
        PS C:\> if(Import-LrtADModule) { "Module Installed" }
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param( )


    # Does Lrt already know if the module is loaded?
    if (! $LrtConfig.ActiveDirectory.ModuleLoaded) {

        # Is the module already loaded?
        if (! (Get-Module -Name ActiveDirectory)) {

            # Can the module be found?
            if (! (Get-Module -ListAvailable -Name ActiveDirectory)) {
                # Module not found
                return $false
            }

            # Attempt to load ActiveDirectory Module - Update LrtConfig
            try {
                Import-Module ActiveDirectory
                $LrtConfig.ActiveDirectory.ModuleLoaded = $true
            } catch {
                # Module failed to load
                return $false
            }
        }
        # Module is loaded, so update LrtConfig with that
        $LrtConfig.ActiveDirectory.ModuleLoaded = $true


        # Determine AD Server / DNSRoot to use for commands, if not explicitly set:
        if ([string]::IsNullOrEmpty($LrtConfig.ActiveDirectory.Server)) {
            try {
                $LrtConfig.ActiveDirectory.Server = (Get-ADDomain).DNSRoot
            } catch {
                Write-Warning "LogRhythm.Tools Config: ActiveDirectory.Server is not set, and a valid DNSRoot could not be found for this host."
                Write-Warning "ActiveDirectory commands will likely fail."
            }
        }


        # Determine which parameters to pass to AD cmdlets - Server, Credential, both, or neither.
        if ($LrtConfig.ActiveDirectory.Credential) {
            if ($LrtConfig.ActiveDirectory.Server) {
                $LrtConfig.ActiveDirectory.Options = "Server+Credential"
            } else {
                $LrtConfig.ActiveDirectory.Options = "Credential"
            }
        } else {
            if ($LrtConfig.ActiveDirectory.Server) {
                $LrtConfig.ActiveDirectory.Options = "Server"
            }
        }
        Write-Verbose "[Import-LrtADModule] AD Options: $Options"

    }
    return $true
}