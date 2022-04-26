# Helper function to build LR Taxonomy Tags
Function New-LrTagTaxObject {
    [CmdletBinding()]
    Param(
        $Primary,
        $Secondary,
        $Tertiary,
        $Value,
        $Note
    )

    $Me = $MyInvocation.MyCommand.Name
    
    $OutputObject = [PSCustomObject]@{
        Primary = $Primary
        Secondary = $Secondary
        Tertiary = $Tertiary
        Value = $Value
        Tag = $null
        Note = $Note
    }

    # Establish Complete Tag
    if ($Secondary -and $Tertiary) { 
        $TagComplete = $Primary+"_"+$Secondary+"_"+$Tertiary+"_"+$Value
    } elseif ($Secondary) {
        $TagComplete = $Primary+"_"+$Secondary+"_"+$Value
    } else {
        $TagComplete = $Primary+"_"+$Value
    }

    $OutputObject.Tag = $TagComplete

    return $OutputObject
}