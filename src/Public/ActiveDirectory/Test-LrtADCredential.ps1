using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace System.DirectoryServices.AccountManagement

Function Test-LrtADCredential {
    <#
    .SYNOPSIS
        Validate an Active Directory username and password. 
    .DESCRIPTION
        The Test-LrtADCredential cmdlet will validate the provided PSCredential object
        against the default AD Domain, or the domain specified in $LrtConfig, if set.
    .PARAMETER Credential
        A PSCredential object for the Active Directory user account to be tested.
    .INPUTS
        A PSCredential object can be sent through the pipeline.
         - or -
        An array of PSCredential objects can be passed as a parameter.
    .OUTPUTS
        Boolean value representing the validation result.
    .EXAMPLE
        Test-LrtADCredential -Credential (Get-Credential)
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline=$true, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential
    )

    Begin {
        # Import Module ActiveDirectory
        if (! (Import-LrtADModule)) {
            throw [Exception] "LogRhythm.Tools Failed to load ActiveDirectory module."
        }


        # Create domain PrincipalContext
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('domain', $LrtConfig.ActiveDirectory.Server)
    }

    
    Process {
        $Return = [PSCustomObject]@{
            Domain    = $LrtConfig.ActiveDirectory.Server
            UserName  = $Credential.UserName
            IsValid   = $false
            Exception = $null
        }

        # Attempt to validate credential. Should something go wrong, capture exception in $Return object.
        try {
            $Return.IsValid = $DS.ValidateCredentials($Credential.UserName, ($Credential.GetNetworkCredential().Password))
        }
        catch {
            $Return.Exception = $PSItem.Exception
        }

    
        return $Return
    
    }
}