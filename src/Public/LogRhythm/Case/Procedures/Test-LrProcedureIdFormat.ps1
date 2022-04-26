using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrProcedureIdFormat {
    <#
    .SYNOPSIS
        Displays formatting information for a given LogRhythm Procedure ID.
    .DESCRIPTION
        The Test-ProcedureId cmdlet displays information about a given LogRhythm Unique 
        Procedure Identifier.
        LogRhythm Procedure IDs can be represented as an RFC 4122 formatted string (Guid), 
        an integer, or by a string.
    .PARAMETER Id
        The LogRhythm Case Id to be tested.
    .INPUTS
        [System.Object] -> Id
    .OUTPUTS
        System.Object with IsGuid, IsValid, Value
    .EXAMPLE
        C:\PS> Test-LrProcedureIdFormat "5831f290-4798-4148-8165-01317d49afea"
        ---
        IsGuid  : True
        IsInt   : False
        IsName  : False
        IsValid : True
        Value   : 5831f290-4798-4148-8165-01317d49afea
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Id
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # Define output object
        $OutObject = [PSCustomObject]@{
            IsGuid      =   $false
            IsInt       =   $false
            IsName      =   $false
            IsValid     =   $false
            Value       =   $Id
        }

        # [ref] for Int.TryParse()
        $_int = 0
    }


    Process {
        # We may have received a full procedure object.  
        # Check to see if it has a property for ID. If it does, use that.
        if ($Id.Id) {
            Write-Verbose "[Test-LrProcedureIdFormat]: Detected Id is a Procedure object. Using Procedure.Id for validation."
            $Id = $Id.Id
        }

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $OutObject.Value = $Id.ToString()
            $OutObject.IsInt = $true
            $OutObject.IsValid = $true
        # Check if ID value is a Guid
        } elseif (($Id -Is [System.Guid]) -Or (Test-Guid $Id)) {
            $OutObject.Value = $Id.ToString()
            $OutObject.IsValid = $true
            $OutObject.IsGuid = $true
        } elseif (($Id -Is [String])) {
            # If it isn't either Guid or Int, and we have a string, then it must be a name.
            $OutObject.IsName = $true
            $OutObject.Value = $Id
            $OutObject.IsValid = $true
        }

        return $OutObject
    }

    
    End { }
}