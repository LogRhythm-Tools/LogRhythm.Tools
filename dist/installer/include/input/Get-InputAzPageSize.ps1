Function Get-InputAzPageSize {
    <#
    .SYNOPSIS 
        Determine if a user entered a valid default page size.
    .PARAMETER Value
        String value representing integer between 1-999
    .EXAMPLE
        PS C:\> Get-InputNumeric -Value 200 -OldValue 500

        Value Valid Changed
        ----- ----- -------
        200    True   False
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue
    )

    # Return object 
    $Return = [PSCustomObject]@{
        Value = $null
        Valid = $false
        Changed = $false
    }

    # Validate Input as Integer between 1-999
    $ValidInt = 0

    if ([int]::TryParse($Value, [ref]$ValidInt)) {
        if (($ValidInt -gt 0) -and ($ValidInt -lt 1000)) {
            # Test passed, return int
            $Return.Valid = $true
            $Return.Value = $ValidInt

            # Is Value different than OldValue
            if ($Return.Value -ne $OldValue) {
                $Return.Changed = $true
            }
        }
    }
    
    return $Return
}