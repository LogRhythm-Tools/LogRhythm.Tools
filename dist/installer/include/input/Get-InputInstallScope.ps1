Function Get-InputInstallScope {
    <#
    .SYNOPSIS 
        Determine if a user entered a valid Install Scope
    .PARAMETER Value
        String to evaluate:
          User
          System
          Skip
    .EXAMPLE
        PS C:\> Get-InputInstallScope -Value 'user' -OldValue 'User'

        Value Valid Changed
        ----- ----- -------
        user   True   False
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $OldValue
    )

    # Validation Regex
    $ValidRegex = [regex]::new("^([Uu]ser|[Ss]ystem|[Ss]kip)$")

    
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