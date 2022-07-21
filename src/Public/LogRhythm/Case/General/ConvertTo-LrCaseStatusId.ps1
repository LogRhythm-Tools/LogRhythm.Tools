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
    .EXAMPLE
        ConvertTo-LrCaseStatusId -Status "Bogus"
        ---
        Code  : 404
        Error : True
        Type  : Invalid status name
        Note  :
        Value : Bogus
        Raw   : [ConvertTo-LrCaseStatusId] No match found for Bogus
    .EXAMPLE
        ConvertTo-LrCaseStatusId -Status 5
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
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Value                 =   $Status
            Raw                   =   $null
        }  

        # Validate Case Status
        $_int = $null
        if (! ([int]::TryParse($Status, [ref]$_int))) {
            Write-Verbose "[$Me]: Status did not parse as Int32"
            if ($LrCaseStatus.$Status) {
                Write-Verbose "[$Me]: Found match for $Status. Return $($LrCaseStatus.Status)"
                return $LrCaseStatus.$Status
            } else {
                $ErrorObject.Code = 404
                $ErrorObject.Error = $true
                $ErrorObject.Raw = "[$Me] No match found for $Status"
                $ErrorObject.Type = 'Invalid status name'
                $ErrorObject.Value = $Status
                Write-Verbose "[$Me]: No match found for $Status"
                return $ErrorObject
            }
        }
        # we have an integer, ensure it is between 1 and 5
        if (($_int -gt 0) -and ($_int -lt 6)) {
            return $_int
        } else {
            $ErrorObject.Code = 404
            $ErrorObject.Error = $true
            $ErrorObject.Raw = "[$Me] No match found for $Status"
            $ErrorObject.Type = 'Invalid status value'
            $ErrorObject.Value = $Status
            Write-Verbose "[$Me]: No match found for $Status"
            return $ErrorObject
        }
        # int outside of range, and not a string.
        return $null
    }

    End { }
}