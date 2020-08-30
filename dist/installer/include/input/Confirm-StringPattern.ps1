using namespace System
Function Confirm-StringPattern {
    <#
    .SYNOPSIS 
        Prompt the user to make a selection from values within a list.
    .PARAMETER Message
        Displayed to the user as the input prompt.
    .EXAMPLE
        PS C:\> 
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,


        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [regex] $Pattern,


        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Hint,


        [Parameter(Mandatory = $false, Position = 3)]
        [string] $OldValue,


        [Parameter(Mandatory = $false, Position = 4)]
        [string[]] $AllowChars
    )

    # Setup Result object
    $Result = [PSCustomObject]@{
        Value   = $null
        Valid   = $false
        Changed = $false
    }


    while (! $Result.Valid) {
        $Response = Read-Host -Prompt $Message
        $Response = $Response.Trim()
        $Response = Remove-SpecialChars -Value $Response -Allow $AllowChars
        

        if($Response -match $Pattern) {
            $Result.Valid = $true
            $Result.Value = $Response
            if ($Response -ne $OldValue) {
                $Result.Changed = $true
            }
        } else {
            Write-Host $Hint -ForegroundColor Magenta
        }
    }

    return $Result
}