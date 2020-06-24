using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrHostIdentifier {
    <#
    .SYNOPSIS
        Update an existing Host entry for the LogRhythm Entity structure with new or updated identifiers.
    .DESCRIPTION
        Updates a Host based on the Id and other required details. Searches existing Hosts by Id. Updates existing Host if the Id exists or adds a new one. 
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
    .OUTPUTS
        Confirmation string returned as result.
        "Identifiers added"
    .EXAMPLE
        PS C:\> Update-LrHostIdentifier -Id 3 -Type dnsname -Value mycoolhost.mydomain.com
        ---
        Identifiers added
    .EXAMPLE
        PS C:\> Update-LrHostIdentifier -Id 3 -Type ipaddress -Value 192.168.2.4
        ---
        Identifiers added
    .EXAMPLE
        PS C:\> Update-LrHostIdentifier -Id "Myexistinghost" -Type dnsname -Value mycoolhost.mydomain.com
        ---
        Identifiers added
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName=$true, Position = 1)]
        [string]$Id,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true, Position = 2)]
        [ValidateSet('ipaddress','dnsname', 'windowsname', ignorecase=$true)]
        [string]$Type,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName=$true,  Position = 3)]
        [string]$Value
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
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LRDeployment.Version
        
        # Integer Reference
        [int32]$_int = 1
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $Type
            Note                  =   $null
            Value                 =   $Value
        }

        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $HostLookup = Get-LrHostDetails -Id $Id
            if ($HostLookup.Error) {
                return $HostLookup
            } else {
                [int32]$Guid = $HostLookup.Id
            }
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $HostLookup = Get-LrHosts -Name $Id -Exact
            if (!$HostLookup) {
                return "[$Me]: Unable to identify host record with exact match to string: $Id."
            } else {
                [int32]$Guid = $HostLookup | Select-Object -ExpandProperty id 
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
                throw [ArgumentException] "RecordStatus [$Type] must be: ipaddress, dnsname, or windowsname"
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
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body 
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        }
        
        #>
        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($Exact) {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        } else {
            return $Response
        }
    }

    End { }
}