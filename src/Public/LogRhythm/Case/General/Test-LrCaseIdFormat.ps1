using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-LrCaseIdFormat {
    <#
    .SYNOPSIS
        Displays formatting information for a given LogRhythm Case ID.
    .DESCRIPTION
        The Test-CaseId cmdlet displays information about a given LogRhythm Unique 
        Case Identifier.
        LogRhythm Case IDs can be represented as an RFC 4122 formatted string (Guid), 
        or by an integer (as seen in the LogRhythm Web Console).
    .PARAMETER Id
        The LogRhythm Case Id to be tested.
    .INPUTS
        [System.Object] -> Id
    .OUTPUTS
        System.Object with IsGuid, IsValid, Value
    .EXAMPLE
        C:\PS> Test-CaseIdFormat "5831f290-4798-4148-8165-01317d49afea"
        IsGuid IsValid Value
        ------ ------- -----
         False    True 181
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
        IsGuid      =   $false
        IsValid     =   $false
        Value       =   $Id
    }

    # https://docs.microsoft.com/en-us/dotnet/api/system.int32.tryparse
    $_int = 0

    # Check if ID value is an integer
    if ([int]::TryParse($Id, [ref]$_int)) {
        Write-Verbose "[$Me]: Id parses as integer."
        $OutObject.Value = $Id.ToString()
        $OutObject.IsValid = $true
    # Check if ID value is a Guid
    } elseif (($Id -Is [System.Guid]) -Or (Test-Guid $Id)) {
        $OutObject.Value = $Id.ToString()
        $OutObject.IsValid = $true
        $OutObject.IsGuid = $true
    }

    return $OutObject
}