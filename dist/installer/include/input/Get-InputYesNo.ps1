Function Get-InputYesNo {
    <#
    .SYNOPSIS 
        Determine if a user indicated yes or no depending on input string.
    .PARAMETER Value
        String to evaluate as yes/no
    .OUTPUTS
        The resulting Value field will either be null, true, or false.

        Null:  An invalid response.       Valid: false
        True:  The user indicated  'yes'  Valid: true
        False: The user indiacated 'no'   Valid: true
    .EXAMPLE
        (Valid Response: Yes)
        
        PS C:> Get-InputYesNo -Value 'no' -OldValue $false

        Value Valid Changed
        ----- ----- -------
        False  True   False

    .EXAMPLE
        (Valid Response: No)
        PS C:> Get-InputYesNo -Value 'bad' -OldValue $false

        Value Valid Changed
        ----- ----- -------
              False    True
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue
    )

    # Validation Regexes
    $YesNo_Regex = [regex]::new("^(([Yy]([Ee][Ss])?)|([Nn][Oo]?))$")
    $Yes_Regex = "^[Yy]([Ee][sS])?$"
    $No_Regex = "^[Nn]([Oo])?$"


    
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
        Changed = $false
        Yes = $null
        No = $null
    }


    
    if($Value -match $YesNo_Regex) {
        $Return.Valid = $true
        if ($Value -match $Yes_Regex) {
            $Return.Value = $true
        }
        if ($Value -match $No_Regex) {
            $Return.Value = $false
        }
    }

    # Is Value different than OldValue
    if ($Return.Value -ne $OldValue) {
        $Return.Changed = $true
    }


    return $Return
}