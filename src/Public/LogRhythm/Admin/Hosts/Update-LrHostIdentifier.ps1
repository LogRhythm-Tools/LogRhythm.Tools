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
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        Confirmation string returned as result.
        "Identifiers added"
    .EXAMPLE
        PS C:\> Update-LrHostIdentifier -Id 3 -Type dnsname -Value mycoolhost.mydomain.com
        ---
        Identifiers added
    .EXAMPLE
        PS C:\> Update-LrHostIdentifier -Id 3 -Type ipaddress -Value 192.168.2.4 -PassThru
        ---
        Identifiers added
    .EXAMPLE
        PS C:\> Update-LrHostIdentifier -Id "Myexistinghost" -Type dnsname -Value mycoolhost.mydomain.com

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
        $Me = $MyInvocation.MyCommand.Name

        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

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

        if ($LrtConfig.LogRhythm.Version -match '7\.4\.[0-6]') {
            # Establish JSON Body contents
            $BodyContents = @([PSCustomObject]@{
                hostIdentifiers = @([PSCustomObject]@{
                    type = $_type
                    value = $Value
                })
            })
        } else {
            # Establish JSON Body contents
            $BodyContents = [PSCustomObject]@{
                hostIdentifiers = @([PSCustomObject]@{
                    type = $_type
                    value = $Value
                })
            }
        }


        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/hosts/$Guid/identifiers/"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"
        
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
        
        # Return output object
        if ($PassThru) {
            return $Response
        }
    }

    End { }
}