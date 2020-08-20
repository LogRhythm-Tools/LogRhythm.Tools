using namespace System

Function ConvertFrom-UnixEpoch {
    <#
    .SYNOPSIS
        Converts a unix timestamp to a System.DateTime object.
    .PARAMETER UnixTime
        Unix Epoch Time in seconds
    .INPUTS
        int -> UnixTime
    .OUTPUTS
        System.DateTime
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
        [int64] $UnixTime
    )


    Begin { }


    Process {
        if (("$UnixTime").length -gt 10 ) {
            (Get-Date -Date "01/01/1970").AddMilliseconds($UnixTime)
        } else {
            (([System.DateTimeOffset]::FromUnixTimeSeconds($UnixTime)).DateTime)
        }
    }


    End { }
}

