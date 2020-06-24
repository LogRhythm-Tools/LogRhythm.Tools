Function Get-LrUserNumber {
    <#
    .SYNOPSIS
        Convert a string into a valid LogRhythm User number.
    .DESCRIPTION
        The Get-LrUserNumber cmdlet will convert an incoming string or
        integer into a valid LogRhythm User Id if it matches
        a valid User Name or if can be parsed as an integer that
        corresponds to a real user number.
    .PARAMETER User
        The User string to parse. For the conversion to be successful
        the string must either parse as an integer or match a valid User name.
    .INPUTS
        System.String -> User
    .OUTPUTS
        System.Int32
    .EXAMPLE
        Get-LrUserNumber -User "Smith, John"
        ---
        5
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [string] $User
    )

    Begin {
        $_int = $null
    }

    Process {
        # Validate User
        if (! ([int]::TryParse($User, [ref]$_int))) {
            # User: name
            Write-Verbose "[$Me]: Verify user name $User"
            try {
                $_user = Get-LrUsers -Name $User -Exact
            } catch { 
                Write-Verbose "[$Me]: Unable to find user name $User"
                return $null
            }
            if ($_user) {
                Write-Verbose "[$Me]: User name verified: $($_user.number)"
                return $_user.number
            }
        } else {
            # User: number
            Write-Verbose "[$Me]: Verify user number $User"
            try {
                $_user = Get-LrUsers | Where-Object { $_.number -eq $User }
            }
            catch {
                Write-Verbose "[$Me]: Unable to find user number $User"
                return $null
            }
            if ($_user) {
                Write-Verbose "[$Me]: User id verified: $($_user.number)"
                return $_user.number
            }
        }
    }

    End { }
}