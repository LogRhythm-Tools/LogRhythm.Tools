Function Test-IsIpAddress {
    <#
    .SYNOPSIS 
        Test if a given IP Address is of a valid format.
    .PARAMETER IPAddress
        IP Address to validate.
    .EXAMPLE
        Test-IsIpAddress -IpAddress 10.64.48.21
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $IpAddress
    )
    
    $RegexIP = [regex] "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    if($IpAddress -match $RegexIP) {
        return $True
    }
    return $False
}