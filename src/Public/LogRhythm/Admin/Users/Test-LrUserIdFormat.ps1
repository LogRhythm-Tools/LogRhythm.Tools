using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrUserIdFormat {
    <#
    .SYNOPSIS
        Displays formatting information for a given LogRhythm User ID.
    .DESCRIPTION
        The Test-CaseId cmdlet displays information about a given LogRhythm Unique 
        User Identifier.
        LogRhythm User IDs can be represented as a string, 
        or by an integer.
    .PARAMETER Id
        The LogRhythm User Id to be tested.
    .INPUTS
        [System.Object] -> Id
    .OUTPUTS
        System.Object with IsInt, IsValid, Value
    .EXAMPLE
        C:\PS> Test-UserIdFormat "123"
        IsInt  IsValid Value
        ------ ------- -----
         True     True 181
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
        [object] $Id
    )

    $OutObject = [PSCustomObject]@{
        IsInt       =   $false
        IsValid     =   $false
        Value       =   $Id
    }

    Begin {
        # https://docs.microsoft.com/en-us/dotnet/api/system.int32.tryparse
        $_int = 0
    }

    Process {
        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $OutObject.Value = $Id.ToString()
            $OutObject.IsValid = $true
            $OutObject.IsInt = $true
        # Check if ID value is a String
        } elseif (($Id -Is [String])) {
            $OutObject.Value = $Id.ToString()
            $OutObject.IsValid = $true
        }
    }

    End {
        return $OutObject
    }
}