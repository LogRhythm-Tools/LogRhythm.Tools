using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-ValidTCPUDPPort {
    <#
    .SYNOPSIS
        Validates if value submitted is an integer and within IANA Port Range.
    .DESCRIPTION
        The Test-ValidTCPUDPPort cmdlet displays information about a given variable.
    .PARAMETER Id
        The parameter to be tested.
    .INPUTS
        [System.Object] -> Id
    .OUTPUTS
        System.Object with IsInt, IsValid, Value
    .EXAMPLE
        C:\PS> Test-ValidTCPUDPPort 53
        IsInt IsValid Value
        ------- -----
        True    53
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

    # https://docs.microsoft.com/en-us/dotnet/api/system.int32.tryparse
    $_int = 1

    # Check if ID value is an integer
    if ([int]::TryParse($Id, [ref]$_int)) {
        Write-Verbose "[$Me]: Id parses as integer."
        $OutObject.Value = $Id.ToString()
        $OutObject.IsInt = $true
        if ([int]$Id -ge 0 -and [int]$Id -le 65535) {
            $OutObject.IsValid = $true
        } else {
            $OutObject.IsValid = $false
        } 
    }

    return $OutObject
}