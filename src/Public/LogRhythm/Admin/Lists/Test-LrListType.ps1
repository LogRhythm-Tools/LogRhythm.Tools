using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrListType {
    <#
    .SYNOPSIS
        Validates provided LogRhythm List type is a valid List type.
    .DESCRIPTION
        The Test-LrListType cmdlet displays information about a given LogRhythm Unique 
        Case Identifier.
    .PARAMETER Id
        The LogRhythm ListType to be tested.
    .INPUTS
        [System.String] -> Id
    .OUTPUTS
        System.Object with IsValid, Value
    .EXAMPLE
        C:\PS> Test-LrListType "commonevent"
        IsValid    Value
        -------    -----
        True    CommonEvent
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position=0
        )]
        [ValidateNotNull()]
        [string] $Id
    )

    $OutObject = [PSCustomObject]@{
        IsValid     =   $false
        Value       =   $Id
    }

    $ValidTypes = @("application", "classification", "commonevent", "host", "location", "msgsource", "msgsourcetype", "mperule", "network", "user", "generalvalue", "entity", "rootentity", "ip", "iprange", "identity", "none")
    if ($ValidTypes.Contains($Id.ToLower())) {
        Switch ($Id.ToLower()) {
            application { 
                $OutObject.IsValid = $true
                $OutObject.Value = "Application" 
            }
            classification { 
                $OutObject.IsValid = $true
                $OutObject.Value = "Classification" 
            }
            commonevent { 
                $OutObject.IsValid = $true
                $OutObject.Value = "CommonEvent" 
            }
            host { 
                $OutObject.IsValid = $true
                $OutObject.Value = "Host" 
            }
            location { 
                $OutObject.IsValid = $true
                $OutObject.Value = "Location" 
            }
            msgsource { 
                $OutObject.IsValid = $true
                $OutObject.Value = "MsgSource" 
            }
            msgsourcetype { 
                $OutObject.IsValid = $true
                $OutObject.Value = "MsgSourceType" 
            }
            mperule { 
                $OutObject.IsValid = $true
                $OutObject.Value = "MPERule" 
            }
            network { 
                $OutObject.IsValid = $true
                $OutObject.Value = "Network" 
            }
            user { 
                $OutObject.IsValid = $true
                $OutObject.Value = "User" 
            }
            generalvalue { 
                $OutObject.IsValid = $true
                $OutObject.Value = "GeneralValue" 
            }
            entity { 
                $OutObject.IsValid = $true
                $OutObject.Value = "Entity" 
            }
            rootentity { 
                $OutObject.IsValid = $true
                $OutObject.Value = "RootEntity" 
            }
            ip { 
                $OutObject.IsValid = $true
                $OutObject.Value = "IP" 
            }
            iprange { 
                $OutObject.IsValid = $true
                $OutObject.Value = "IPRange" 
            }
            identity { 
                $OutObject.IsValid = $true
                $OutObject.Value = "Identity" 
            }
            none { 
                $OutObject.IsValid = $true
                $OutObject.Value = "None" 
            }
        }        
    } else {
        $OutObject.IsValid = $false
    }

    return $OutObject
}