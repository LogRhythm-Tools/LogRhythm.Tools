Function Test-LrtADUserExists {
    <#
    .SYNOPSIS 
        Return true if user exists in ActiveDirectory, false if not.
    .PARAMETER Identity
        User identity to check
    .EXAMPLE
        if(Test-LrtADUserExists -Identity bjones) { "User Exists." }
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)] 
        [ValidateNotNullOrEmpty()]
        [string] $Identity
    )

    return (Get-LrtADUserInfo -Identity $Identity).Exists
}