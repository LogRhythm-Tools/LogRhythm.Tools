using namespace System
Function Get-StringPattern {
    <#
    .SYNOPSIS 
        Prompt the user to make a selection from values within a list.
    .PARAMETER Value
        String to evaluate against the provided pattern.
    .PARAMETER OldValue
        A second value to compare to Value, to determine if Value is new.
    .PARAMETER Pattern
        A regular expression pattern used to validate the user's response.
    .PARAMETER AllowChars
        An array of special characters which are allowed to be present in the value string.
    .EXAMPLE
        PS C:\> 
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue,


        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNull()]
        [regex] $Pattern,


        [Parameter(Mandatory = $false, Position = 3)]
        [string[]] $AllowChars
    )

    # Setup Result object
    $Result = [PSCustomObject]@{
        Value   = $null
        Valid   = $false
        Changed = $false
    }

    # Strip special characters
    $Value = Remove-SpecialChars -Value $Value -Allow $AllowChars

    # Validate value
    if($Value -match $Pattern) {
        $Result.Valid = $true
        $Result.Value = $Value
        # Determine if value was changed
        if ($Response -ne $OldValue) {
            $Result.Changed = $true
        }
    }

    return $Result
}