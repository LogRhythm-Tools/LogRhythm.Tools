using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Test-ValidIPv4Address {
    <#
    .SYNOPSIS
        Validates if value submitted is a valid IPv4 Address.
    .DESCRIPTION
        The Test-ValidIPv4Address cmdlet displays information about a given variable.
    .PARAMETER Id
        The parameter to be tested.
    .INPUTS
        [System.Object] -> Id
    .OUTPUTS
        System.Object with IsInt, IsValid, Value, IsPrivate
    .EXAMPLE
        C:\PS> Test-ValidIPv4Address 192.168.5.1
           IsValid   Value         IsPrivate
           -----     -----         -----
           True      192.168.5.1   True
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools     
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $IP
    )

    $OutObject = [PSCustomObject]@{
        IsValid     =   $false
        Value       =   $IP
        IsPrivate   =   $false
    }

    # Check if IP value is a valid IP address, and is IPv4 by parsing it as an [ipaddress]
    if (($IP -as [ipaddress]) -and ($IP -as [ipaddress]).AddressFamily -eq 'InterNetwork') {
        $OutObject.Value = $IP.ToString()
        $OutObject.IsValid = $true
        if ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') {
            $OutObject.IsPrivate = $true
        }
        else {
            $OutObject.IsPrivate = $false
        }

        if ($IP -match '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))') {
            $OutObject.IsValid = $false
        }
    } else {
        $OutObject.IsValid = $false
    }

    return $OutObject
}