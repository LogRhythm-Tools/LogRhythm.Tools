using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrIdentityIdentifierValue {
    <#
    .SYNOPSIS
        Identifies if provided Identifier Value is a member of a specific True Identitiy.
    .DESCRIPTION
        The Test-LrIdentityIdentifierValue cmdlet displays information about a given value's
        presence on a specific LogRhythm True Identity.
    .PARAMETER Value
        The Value of the Identifier Object
    .PARAMETER IdentifierType
        The Identifier type.  Login or Email
    .PARAMETER IdentityId
        The TrueIdentity ID #
    .INPUTS
        [System.String] -> Value   The Value parameter can be provided via the PowerShell pipeline.
        [System.String] -> Name
    .OUTPUTS
        System.Object with IsPresent, Value, ValueType, ListValid, ListName, ListGuid
    .EXAMPLE
        C:\PS> Test-LrIdentityIdentifierId -Id 51 -IdentityId 1
        ----
        IsPresent           : True
        IdentifierId        : 51
        Value               : marcus.burnett2@contaso.com
        IdentifierType      : Email
        IdentifierValid     : True
        IdentityId          : 1
        IdentityValid       : True
        IdentityStatus      : Active
        IdentityDisplayName : marcus.burnett@fabrikam.com
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position=0)]
        [ValidateNotNull()]
        [string] $Value,

        [Parameter(Mandatory = $true,Position=1)]
        [ValidateNotNull()]
        [string] $IdentifierType,

        [Parameter(Mandatory = $true,Position=2)]
        [ValidateNotNull()]
        [int] $IdentityId
    )
    Begin {
        # Establish output object
        $OutObject = [PSCustomObject]@{
            IsPresent           =   $false
            IdentifierId        =   $null
            Value               =   $Value
            IdentifierType      =   $IdentifierType
            IdentifierValid     =   $null
            IdentityId          =   $IdentityId
            IdentityValid       =   $null
            IdentityStatus      =   $null
            IdentityDisplayName =   $null
        }

        # Process IdentityId
        $IdentityResponse = Get-LrIdentityById -IdentityId $IdentityId -Silent

        # Verify target Identity exists and add basic information
        if ($IdentityResponse -ne "404") {
            $OutObject.IdentityValid = $true
            $OutObject.IdentityStatus = $IdentityResponse.recordStatus
            $OutObject.IdentityDisplayName = $IdentityResponse.displayIdentifier
        } else {
            $OutObject.IdentityValid = $false
        }

        # Process IdentifierType
        $IdentityTypeResponse = Test-LrIdentifierType -IdentifierValue $Value -IdentifierType $IdentifierType

        # Verify Identifier Value matches IdentityType formatting and sanatize IdentifierType punctuation
        if ($IdentityTypeResponse.IsValid) {
            $IdentifierType = $IdentityTypeResponse.Type
            $OutObject.IdentifierType = $IdentityTypeResponse.Type
            $OutObject.IdentifierValid = $true
        } else {
            $OutObject.IdentifierValid = $false
        }
    }

    Process {
        if ($OutObject.IdentityValid -eq $true -and $OutObject.IdentifierValid -eq $True) {
            # Review each item from ListItems and compare to Parameter Value
            foreach ($Identifier in $($IdentityResponse.identifiers)) {
                if ($Identifier.identifierType -eq $IdentifierType) {
                    if ($Identifier.value -eq $Value) {
                        $OutObject.IsPresent = $true
                        $OutObject.IdentifierId = $Identifier.identifierID
                    }
                }
            }
        }

        Return $OutObject
    }

    End { }
}