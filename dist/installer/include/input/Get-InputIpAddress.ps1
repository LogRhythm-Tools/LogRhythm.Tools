Function Get-InputIpAddress {
    <#
    .SYNOPSIS 
        Determine if a user entered a valid IP Address
    .PARAMETER Value
        String to evaluate as an IP Address
    .EXAMPLE
        PS C:\> Get-InputIpAddress -Value 10.1.1.1 -OldValue 10.1.1.1

        Value    Valid Changed
        -----    ----- -------
        10.1.1.1  True   False
    .EXAMPLE
        PS C:\> Get-InputIpAddress -Value 10.1.1.11111 -OldValue 10.1.1.5

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
    $ValidRegex = [regex]::new("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    
    
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