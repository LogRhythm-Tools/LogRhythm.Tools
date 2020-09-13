using namespace System
using namespace System.Collections.Generic
using namespace Microsoft.ActiveDirectory.Management

Function Test-LrtADUserExists {
    <#
    .SYNOPSIS 
        Determine if the provided ADUser Identity can be found in the default
        AD Domain, or the domain specified in $LrtConfig, if set.
    .PARAMETER Identity
        User identity to test.
    .INPUTS
        [ADUser] => Identity
    .OUTPUTS
        True if the user was found in the directory, otherwise false.
    .EXAMPLE
        PS C:\> Test-LrtADUserExists -Identity "bobjonesBAD"
        
        ---
        False
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [ADUser] $Identity
    )


    Begin { }

    
    Process {

        try {
            Get-LrtADUser -Identity $Identity | Out-Null
        } catch {
            return $false
        }

        return $true
    }


    End { }
}