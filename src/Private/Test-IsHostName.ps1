Function Test-IsHostname {
    <#
    .SYNOPSIS 
        Test if a given hostname is valid per RFC 1123.
    .PARAMETER IPAddress
        Hostname to validate.
    .EXAMPLE
        Test-IsHostname -Hostname 10.64.48.21
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string] $Hostname
    )
    
    $RegexHostname = [regex] "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
    if($Hostname -match $RegexHostname) {
        return $True
    }
    return $False
}