using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrIdentityIdentifierId {
    <#
    .SYNOPSIS
        Identifies if provided Identifier ID is a member of a specific True Identitiy.
    .DESCRIPTION
        The Test-LrIdentityIdentifierId cmdlet displays information about a given value's
        presence on a specific LogRhythm True Identity.
    .PARAMETER Id
        The Value of the Identifier Object
    .PARAMETER IdentityId
        The TrueIdentity ID #
    .INPUTS
        [System.String] -> Value   The Value parameter can be provided via the PowerShell pipeline.
        [System.String] -> Name
    .OUTPUTS
        System.Object with IsPresent, Value, ValueType, ListValid, ListName, ListGuid
    .EXAMPLE
        C:\PS> Test-LrIdentityIdentifier -Id 44 -IdentityId 1
            IsPresent : True
            Value     : 192.168.5.1
            ValueType : IP
            ListValid : True
            ListName  : srfIP
            ListGuid  : 81059751-823E-4F5B-87BE-FEFFF1708E5E
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position=0)]
        [ValidateNotNull()]
        [int] $Id,

        [Parameter(Mandatory = $true,Position=1)]
        [ValidateNotNull()]
        [int] $IdentityId
    )
    Begin {
        # Establish output object
        $OutObject = [PSCustomObject]@{
            IsPresent           =   $false
            IdentifierId        =   $Id
            Value               =   $null
            IdentifierType      =   $null
            RecordStatus        =   $null
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
    }

    Process {
        if ($OutObject.IdentityValid -eq $true) {
            # Review each item from ListItems and compare to Parameter Value
            foreach ($Identifier in $($IdentityResponse.identifiers)) {
                if ($Identifier.identifierID -eq $Id) {
                    $OutObject.IsPresent = $true
                    $OutObject.Value = $Identifier.value
                    $OutObject.IdentifierType = $Identifier.identifierType
                    $OutObject.RecordStatus = $Identifier.recordStatus
                }
            }
        }

        Return $OutObject
    }

    End { }
}