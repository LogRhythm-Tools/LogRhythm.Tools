using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Remove-LrHostIdentifier {
    <#
    .SYNOPSIS
        Update an existing Host entry for the LogRhythm Entity structure and remove existing identifiers.
    .DESCRIPTION
        Searches existing Hosts by Id. If the Id exists, the Host Identifiers are removed. 
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        Integer or String for existing Host.  If a string is provided an exact lookup will be performed to identify the Integer Id.
    .PARAMETER Type
        Parameter for specifying the existing LogRhythm Entity for the new Host record to be set to.  
        This parameter can be provided either Entity Name or Entity Id but not both.

        Valid Types: "IPAddress" "DNSName" "WindowsName"
    .PARAMETER Value
        [System.String] Parameter for specifying a new identifier value.
        
        Max length: 50 characters
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        Confirmation string returned as result.
        "Identifiers removed"
    .EXAMPLE
        PS C:\> Remove-LrHostIdentifier -Id 3 -Type dnsname -Value mycoolhost.mydomain.com

    .EXAMPLE
        PS C:\> Remove-LrHostIdentifier -Id 3 -Type ipaddress -Value 192.168.2.4 -PassThru
        ---
        Identifiers removed
    .EXAMPLE
        PS C:\> Remove-LrHostIdentifier -id "Myexistinghost" -Type dnsname -Value mycoolhost.mydomain.com

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Id,

        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateSet('ipaddress','dnsname', 'windowsname', ignorecase=$true)]
        [string] $Type,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true,  Position = 2)]
        [string] $Value,

        
        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Delete

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LRDeployment.Version
        
        # Integer Reference
        [int32] $_int = 1
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $Type
            Note                  =   $null
            Value                 =   $Value
            Raw                   =   $null
        }

        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $HostLookup = Get-LrHostDetails -Id $Id
            if ($HostLookup.Error) {
                return $HostLookup
            } else {
                [int32] $Guid = $HostLookup.Id
            }
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $HostLookup = Get-LrHosts -Name $Id -Exact
            if (!$HostLookup) {
                $ErrorObject.Error = $true
                $ErrorObject.Code = 404
                $ErrorObject.Note = "Unable to identify host record with exact match to string: $Id."
                return $ErrorObject
            } else {
                [int32] $Guid = $HostLookup | Select-Object -ExpandProperty id 
            }
        }

        # Ensure proper syntax RecordStatus
        if ($Type) {
            $ValidStatus = @("ipaddress", "dnsname", "windowsname")
            if ($ValidStatus.Contains($($Type.ToLower()))) {
                if ($($Type.ToLower()) -eq "ipaddress") {
                    $IPResults = Test-ValidIPv4Address $Value
                    if ($IPResults.IsValid -eq $True) {
                        $_type = "IPAddress"
                    } else {
                        $ErrorObject.Error = $true
                        $ErrorObject.Code = 500
                        $ErrorObject.Note = "Value Type: ipaddress Value: $Value does not pass Test-ValidIPv4Address"
                        return $ErrorObject
                    }
                } elseif ($($Type.ToLower()) -eq "dnsname") {
                    $_type = "DNSName"
                } else {
                    $_type = "WindowsName"
                }
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Note = "RecordStatus [$Type] must be: ipaddress, dnsname, or windowsname"
                return $ErrorObject
            }
        }


        # Establish JSON Body contents
        $BodyContents = [PSCustomObject]@{
            hostIdentifiers = @([PSCustomObject]@{
                type = $_type
                value = $Value
            })
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json

        Write-Verbose "$Body"

        # Define Query URL
        $RequestUrl = $BaseUrl + "/hosts/$Guid/identifiers/"

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body 
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        
        # Return output object
        if ($ErrorObject.Error -eq $true) {
            return $ErrorObject
        }
        if ($PassThru) {
            return $Response
        }
    }

    End { }
}