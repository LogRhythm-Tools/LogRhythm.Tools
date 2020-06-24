Function Test-Guid {
    <#
    .SYNOPSIS
        Determine if a given string is a valid Guid.
    .DESCRIPTION
        xxxx
    .PARAMETER Guid
        The string to be tested.
    .INPUTS
        System.String - Guid to be tested
    .OUTPUTS
        System.Boolean
            True if string is a valid Guid
            False if string is not a valid Guid
    .EXAMPLE
        PS > "edea82e3-8d0b-4370-86f0-d96bcd4b6c19" | Test-Guid
        True
    .EXAMPLE
        PS > Test-Guid "edea82e3-8d0b-4370-86f0-d96bcd4b6c19"
        True
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0, ValueFromPipeline=$true)]
        [string] $Guid
    )

    if ([string]::IsNullOrEmpty($Guid)) {
        return $false
    }
    $ValidGuid = [guid]::Empty
    if (! ([guid]::TryParse($Guid, [ref]$ValidGuid))) {
        return $false
    }
    return $true
}