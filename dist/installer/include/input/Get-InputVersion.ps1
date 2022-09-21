Function Get-InputVersion {
    <#
    .SYNOPSIS 
        Determine if a user entered a valid version, in the form of 
        x.y.z or
        x.y.zz
    .PARAMETER Value
        String to evaluate
    .EXAMPLE
        PS C:\> Get-InputVersion -Value 7.1.1 -OldValue 7.5.5

        Value Valid Changed
        ----- ----- -------
        7.1.1  True    True
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue
    )

    # Validation Regexes
    $ValidRegex = [regex]::new("^[1-9]\.\d+\.\d+?$")

    
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
        Changed = $false
    }


    if($Value -match $ValidRegex) {
        $Return.Valid = $true
        $Return.Value = $Value
    }

    
    # Is Value different than OldValue
    if ($Return.Value -ne $OldValue) {
        $Return.Changed = $true
    }

    
    return $Return
}