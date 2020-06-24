function Compare-StringArrays {
    <#
    #> 
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [string[]]$Array1,
        
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [string[]]$Array2,
        
        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNull()]
        [switch]$Unsorted
    ) 
        
    $occurrences = if ($unsorted.IsPresent) { @{} }
                   else { [Collections.Generic.SortedDictionary[string,int]]::new() }
    foreach ($_ in $Array1) { $occurrences[$_]++ }
    foreach ($_ in $Array2) { $occurrences[$_]-- }
    foreach ($_ in $occurrences.GetEnumerator()) {
        $Cnt = $_.value
        if ($Cnt) {
            $Diff = [PSCustomObject]@{
                InputObject = $_.key
                SideIndicator = if ($Cnt -lt 0) { '=>' } else { '<=' }
            }
            $cnt = [Math]::Abs($cnt)
            while ($Cnt--) {
                $Diff
            }
        }
    }
}