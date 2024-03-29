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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position=0)]
        [ValidateNotNull()]
        [object] $Id
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # [Ref] placeholder for TryParse
        $_int = 0
    }

    Process {
        $OutObject = [PSCustomObject]@{
            IsInt       =   $false
            IsName      =   $false
            IsValid     =   $false
            Value       =   $Id
        }
        
        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $OutObject.IsValid = $true
            $OutObject.IsInt = $true
        # Check if ID value is a String
        } elseif (($Id -Is [String])) {
            $OutObject.IsName = $true
            $OutObject.IsValid = $true
        }

        return $OutObject
    }

    End {
        
    }
}