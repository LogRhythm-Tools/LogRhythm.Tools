using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Test-LrIdentifierType {
    <#
    .SYNOPSIS
        Validates provided LogRhythm List type is a valid List type.
    .DESCRIPTION
        The Test-LrListType cmdlet displays information about a given LogRhythm Unique 
        Case Identifier.
    .PARAMETER IdentifierValue
        The 
    .PARAMETER IdentifierType
        The LogRhythm IdentifierType to be tested.
    .INPUTS
        [System.String] -> IdentifierValue
        [System.String] -> IdentifierType
    .OUTPUTS
        System.Object with IsValid, IdentifierValue, IdentifierType
    .EXAMPLE
        C:\PS> Test-LrIdentifierType "commonevent"
        IsValid    IdentifierValue    IdentifierType
        -------    ---------------    --------------
        True       tstr@example.com   Email
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position=0)]
        [ValidateNotNull()]
        [string] $IdentifierValue,

        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position=1)]
        [string] $IdentifierType
    )
    Begin { }

    Process {
        # Define return object
        $OutObject = [PSCustomObject]@{
            IsValid     =   $false
            Value       =   $IdentifierValue
            Type        =   $IdentifierType
        }

        # Perform type validation
        Switch ($IdentifierType) {
            "email" { 
                $OutObject.IsValid = $($IdentifierValue -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$")
                $OutObject.Value = $IdentifierValue 
                $OutObject.Type = "Email"
            }
            "login" { 
                $OutObject.IsValid = $true
                $OutObject.Value = $IdentifierValue 
                $OutObject.Type = "Login" 
            }
            default {
                $OutObject.IsValid = $false
            }
        } 

        return $OutObject
    }
    
    End { }
}