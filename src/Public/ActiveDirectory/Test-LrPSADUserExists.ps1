Function Test-LrPSADUserExists {
    <#
    .SYNOPSIS 
        Return true if user exists in ActiveDirectory, false if not.
    .PARAMETER Identity
        User identity to check
    .EXAMPLE
        if(Test-LrPSADUserExists -Identity bjones) { "User Exists." }
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)] 
        [ValidateNotNullOrEmpty()]
        [string] $Identity
    )

    return (Get-LrPSADUserInfo -Identity $Identity).Exists
}