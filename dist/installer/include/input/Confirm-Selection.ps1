using namespace System
using namespace System.IO
using namespace System.Collections.Generic
using namespace System.Text.RegularExpressions

Function Confirm-Selection {
    <#
    .SYNOPSIS 
        Prompt the user to make a selection from a collection of values.
    .PARAMETER Message
        Displayed to the user as the input prompt.
    .PARAMETER Values
        A collection of strings representing the valid responses to this selection.
    .PARAMETER OldValue
        An optional value to compare to the newly chosen value, to determine if the selection has changed.
    .PARAMETER CaseSensitive
        Setting this switch will ensure that input must match the casing of the strings within the $Values collection.
    .EXAMPLE
        PS C:\> Confirm-Selection -Message "Chose One" -Values @("Apple","Pear","Orange")

        Chose One: apple
        ---
        Value Valid Changed
        ----- ----- -------
        apple  True    True

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Message,


        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [string[]] $Values,


        [Parameter(Mandatory = $false, Position = 2)]
        [string] $OldValue,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $CaseSensitive
    )

    # Setup Result object
    $Result = [PSCustomObject]@{
        Value = $null
        Valid = $false
        Changed = $false
    }


    # Setup: Case [In]sensitive
    if (! $CaseSensitive) {
        # Make $Values all lower (for hinting)
        for ($i = 0; $i -lt $Values.Count; $i++) {
            $Values[$i] = $Values[$i].ToLower()
        }

        # Values to RegEx patterns
        $Patterns = [List[regex]]::new()
        foreach ($pattern in $Values) {
            $pattern = "^" + $pattern
            $pattern += "$"
            Write-Verbose "Pattern: $pattern"
            $Patterns.Add([regex]::new($pattern, [RegexOptions]::IgnoreCase))
        }
    }


    # Build Hint
    $Hint = "  Hint: ("
    $x = 0
    foreach ($item in $Values) {
        if ($x -gt 0) { $Hint += "|" }
        $Hint += $item
        $x++
    }
    $Hint += ")"


    # Get Input    
    while (! $Result.Valid) {
        $Response = Read-Host -Prompt $Message
        $Response = $Response.Trim()
        $Response = Remove-SpecialChars -Value $Response -Allow @("-",".")
        
        # Find Match - Case Sensitive ("contains" is exact matching)
        if ($CaseSensitive) {
            if ($Values.Contains($Response)) {
                $Result.Value = $Response
                $Result.Valid = $true
            }
            
        # Find Match - Case [In]sensitive (using regex $Patterns)
        } else {
            foreach ($pattern in $Patterns) {
                if ($Response -match $pattern) {
                    $Result.Value = $Response
                    $Result.Valid = $true
                }
            }
        }

        # Provide Hint
        if (! $Result.Valid) {
            Write-Host $Hint -ForegroundColor Magenta    
        }
    }


    # Check for change
    if ($Result.Value -ne $OldValue) {
        $Result.Changed = $true
    }

    return $Result

    
}