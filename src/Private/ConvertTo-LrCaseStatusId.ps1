Function ConvertTo-LrCaseStatusId {
    <#
    .SYNOPSIS
        Convert a string into a valid LogRhythm Case Status Id (1-5).
    .DESCRIPTION
        The ConvertTo-LrCaseStatusId cmdlet will convert an incoming string or
        integer into a valid LogRhythm Case Status Id if it matches
        a valid Status Name or if can be parsed as an integer of 1-5.
    .PARAMETER Status
        The status string to parse. For the conversion to be successful
        the string must either parse as an integer of 1-5 or match
        a valid status name.
    .INPUTS
        System.String -> Status
    .OUTPUTS
        System.Int32 or System.Object[]
    .EXAMPLE
        ConvertTo-LrCaseStatusId -Status "Closed"
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
        [string] $Status
    )

    Begin { 
        $Me = $MyInvocation.MyCommand.Name
    }

    Process {
        # Validate Case Status
        $_int = $null
        if (! ([int]::TryParse($Status, [ref]$_int))) {
            Write-Verbose "[$Me] Status did not parse as Int32"
            if ($LrCaseStatus.$Status) {
                Write-Verbose "[$Me] Found match for $Status. Return $($LrCaseStatus.Status)"
                return $LrCaseStatus.$Status
            } else {
                Write-Verbose "[$Me] No match found for $Status"
                return $null
            }
        }
        # we have an integer, ensure it is between 1 and 5
        if (($_int -gt 0) -and ($_int -lt 6)) {
            return $_int
        }
        # int outside of range, and not a string.
        return $null
    }

    End { }
}