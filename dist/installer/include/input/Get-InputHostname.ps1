Function Get-InputHostname {
    <#
    .SYNOPSIS 
        Determine if a user entered a valid hostname, according to RFC 1123.
    .PARAMETER Value
        String to evaluate
    .EXAMPLE
        PS C:\> Get-InputHostname -Value hostname.com -OldValue oldhostname.com

        Value         Valid Changed
        -----         ----- -------
        hostname.com  True    True
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
    $ValidRegex = 
        [regex]::new("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")



    
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