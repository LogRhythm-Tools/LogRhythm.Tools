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
        https://github.com/SmartResponse-Framework/SmartResponse.Framework        
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position=0
        )]
        [ValidateNotNull()]
        [string] $IP
    )

    $OutObject = [PSCustomObject]@{
        IsValid     =   $false
        Value       =   $IP
        IsPrivate   =   $false
    }

    # Check if ID value is an integer
    if ($IP -as [ipaddress]) {
        $OutObject.Value = $IP.ToString()
        $OutObject.IsValid = $true
        if ($IP -Match '(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)') {
            $OutObject.IsPrivate =$true
        }
        else {
            $OutObject.IsPrivate = $false
        }
    } else {
        $OutObject.IsValid = $false
    }

    return $OutObject
}