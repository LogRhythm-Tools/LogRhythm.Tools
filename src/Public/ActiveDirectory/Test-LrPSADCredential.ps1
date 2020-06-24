using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace System.DirectoryServices.AccountManagement

Function Test-LrPSADCredential {
    <#
    .SYNOPSIS
        Validate an Active Directory user account credential object against the local domain.
    .PARAMETER Credential
        A PSCredential object for the Active Directory user account to be tested.
    .INPUTS
        A PSCredential object can be sent through the pipeline.
         - or -
        An array of PSCredential objects can be passed as a parameter.
    .OUTPUTS
        Boolean value representing the validation result.
    .EXAMPLE
        Test-LrPSADCredential -Credential (Get-Credential)
    .LINK       
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [ValidateNotNull()]
        [pscredential[]] $Credential
    )

    Begin {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('domain')
    }

    Process {
        foreach ($Cred in $Credential) {
            $DS.ValidateCredentials($Cred.UserName, ($Cred.GetNetworkCredential().Password))
        }
    }
}