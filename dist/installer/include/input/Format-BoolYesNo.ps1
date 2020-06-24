function Format-BoolYesNo {
    <#
    .SYNOPSIS
        Turns a bool value into the string "Yes" or "No"
    .DESCRIPTION
        This might seem silly, but there may be a reusable
        use case for this, or it may indicate a future
        need for various input/output formatting, given
        the dynamic nature of the installer module.
    .PARAMETER Value
        Boolean to parse as yes/no
    .INPUTS
        [bool] => Value
    .OUTPUTS
        [string]
    .EXAMPLE
        PS C:\> Format-BoolYesNo -Value $false

        No
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            Position = 0)]
        [bool] $Value
    )


    Process {
        if ($Value) {
            return "Yes"
        }
        return "No"
    }
}