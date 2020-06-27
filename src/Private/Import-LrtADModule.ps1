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
    }
    return $true
}