using namespace System
Function Confirm-YesNo {
    <#
    .SYNOPSIS 
        Prompt the user for a yes/no answer.
    .PARAMETER Message
        Displayed to the user as
    .EXAMPLE
        PS C:\> 
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [string] $Message,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet(
            'Black',
            'DarkBlue',
            'DarkGreen',
            'DarkCyan',
            'DarkRed',
            'DarkMagenta',
            'DarkYellow',
            'Gray',
            'DarkGray',
            'Blue',
            'Green',
            'Cyan',
            'Red',
            'Magenta',
            'Yellow',
            'White'
        )]
        [string] $ForegroundColor = 'White',

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet("Yes","No")]
        [string] $Default = "No"
    )


    $Message = $Message + " : "
    # Set Hint + Padding
    $Hint = "  Hint: (yes|no)"


    while (! $Result.Valid) {
        Write-Host $Message -ForegroundColor $ForegroundColor -NoNewline
        $Response = Read-Host
        $Response = $Response.Trim()
        if ([string]::IsNullOrEmpty($Response)) {
            $Response = $Default
        }
        $Result = Get-InputYesNo -Value $Response

        if ($Result.Valid) {
            return $Result.Value
        }
        Write-Host $Hint -ForegroundColor Magenta
    }
}