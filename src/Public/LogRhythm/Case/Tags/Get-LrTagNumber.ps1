Function Get-LrTagNumber {
    <#
    .SYNOPSIS
        Convert a string into a valid LogRhythm Tag number.
    .DESCRIPTION
        The Get-LrTagNumber cmdlet will convert an incoming string or
        integer into a valid LogRhythm Tag number if it matches
        a valid Tag Name or if can be parsed as an integer that
        corresponds to a real Tag number.
    .PARAMETER Tag
        The Tag string to parse. For the conversion to be successful
        the string must either parse as an integer or match a valid Tag name.
    .INPUTS
        System.String -> Tag
    .OUTPUTS
        System.Int32
    .EXAMPLE
        Get-LrTagNumber -Tag "Malware"
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
        [string] $Tag
    )

    Begin {
        $_int = 1
     }

    Process {
        # Validate Tag

        if (! ([int]::TryParse($Tag, [ref]$_int))) {
            # Tag: name
            Write-Verbose "[$Me]: Verify Tag name $Tag"
            $_tag = Get-LrTags -Name $Tag -Exact
            if ($_tag.Error -eq $true) {
                return $_tag
            } else {
                Write-Verbose "[$Me]: Tag name verified: $($_tag.number)"
                return $_tag.number
            }
        } else {
            # Tag: number
            Write-Verbose "[$Me]: Verify Tag number $Tag"
            $_tag = Get-LrTag -Number $Tag
            if ($_tag.Error -eq $true) {
                return $_tag
            } else {
                Write-Verbose "[$Me]: Tag name verified: $($_tag.number)"
                return $_tag.number
            }
        }
    }

    End { }
}