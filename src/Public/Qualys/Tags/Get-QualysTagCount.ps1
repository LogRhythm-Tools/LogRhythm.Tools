using namespace System
using namespace System.Collections.Generic

Function Get-QualysTagCount {
    <#
    .SYNOPSIS
        Get count of Qualys tags.
    .DESCRIPTION
        Returns a count of tags that match the provided criteria. This is useful for
        counting child tags of a parent tag or getting a count before retrieving all tags.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        Filter by tag ID.
    .PARAMETER Name
        Filter by tag name (supports partial matches).
    .PARAMETER Parent
        Filter by parent tag ID. Use this to count all children of a specific tag.
    .PARAMETER RuleType
        Filter by rule type.

        Valid values: STATIC, GROOVY, OS_REGEX, NETWORK_RANGE, NAME_CONTAINS, INSTALLED_SOFTWARE,
        OPEN_PORTS, VULN_EXIST, ASSET_SEARCH, CLOUD_ASSET
    .PARAMETER Provider
        Filter by cloud provider.

        Valid values: EC2, AZURE, GCP, IBM, OCI
    .PARAMETER Color
        Filter by tag color (hex format: #FFFFFF).
    .OUTPUTS
        Integer representing the count of matching tags.
    .EXAMPLE
        PS C:\> Get-QualysTagCount

        Returns the total count of all tags.
    .EXAMPLE
        PS C:\> Get-QualysTagCount -Parent 12345

        Returns the count of all child tags under parent tag ID 12345.
    .EXAMPLE
        PS C:\> Get-QualysTagCount -Name "Production"

        Returns the count of tags with "Production" in the name.
    .EXAMPLE
        PS C:\> Get-QualysTagCount -RuleType "CLOUD_ASSET" -Provider "AZURE"

        Returns the count of Azure cloud asset tags.
    .NOTES
        Qualys-API v2.0

        Permissions required: Managers with full scope, other users must have
        Access Permission "API Access"
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [int] $Id,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Name,

        [Parameter(Mandatory = $false, Position = 2)]
        [int] $Parent,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('STATIC', 'GROOVY', 'OS_REGEX', 'NETWORK_RANGE', 'NAME_CONTAINS', 'INSTALLED_SOFTWARE',
                     'OPEN_PORTS', 'VULN_EXIST', 'ASSET_SEARCH', 'CLOUD_ASSET', ignorecase=$true)]
        [string] $RuleType,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('EC2', 'AZURE', 'GCP', 'IBM', 'OCI', ignorecase=$true)]
        [string] $Provider,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidatePattern('^#[0-9A-Fa-f]{6}$')]
        [string] $Color,

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Qualys.Credential
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        # Request Setup
        $BaseUrl = $LrtConfig.Qualys.BaseUrl
        $Username = $Credential.GetNetworkCredential().UserName
        $Password = $Credential.GetNetworkCredential().Password

        # Create Basic Auth Header
        $Headers = [Dictionary[string,string]]::new()
        $AuthString = "$Username`:$Password"
        $AuthBytes = [System.Text.Encoding]::UTF8.GetBytes($AuthString)
        $AuthBase64 = [System.Convert]::ToBase64String($AuthBytes)
        $Headers.Add("Authorization", "Basic $AuthBase64")
        $Headers.Add("Content-Type", "text/xml")

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code  = $null
            Error = $false
            Type  = $null
            Note  = $null
            Value = $null
            Raw   = $null
        }

        # Build XML Request Body
        $XmlBuilder = [System.Text.StringBuilder]::new()
        [void]$XmlBuilder.AppendLine('<ServiceRequest>')

        # Add filters if provided
        $HasFilters = $false
        if ($Id -or $Name -or $Parent -or $RuleType -or $Provider -or $Color) {
            [void]$XmlBuilder.AppendLine('    <filters>')
            $HasFilters = $true
        }

        if ($Id) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"id`" operator=`"EQUALS`">$Id</Criteria>")
        }

        if ($Name) {
            $EncodedName = [System.Security.SecurityElement]::Escape($Name)
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"name`" operator=`"CONTAINS`">$EncodedName</Criteria>")
        }

        if ($Parent) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"parent`" operator=`"EQUALS`">$Parent</Criteria>")
        }

        if ($RuleType) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"ruleType`" operator=`"EQUALS`">$RuleType</Criteria>")
        }

        if ($Provider) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"provider`" operator=`"EQUALS`">$Provider</Criteria>")
        }

        if ($Color) {
            $EncodedColor = [System.Security.SecurityElement]::Escape($Color)
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"color`" operator=`"EQUALS`">$EncodedColor</Criteria>")
        }

        if ($HasFilters) {
            [void]$XmlBuilder.AppendLine('    </filters>')
        }

        [void]$XmlBuilder.AppendLine('</ServiceRequest>')

        $RequestBody = $XmlBuilder.ToString()
        Write-Verbose "[$Me]: Request Body:`n$RequestBody"

        # Define URL
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/count/am/tag"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers -Body $RequestBody

            # Parse XML response
            if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                $Count = [int]$Response.ServiceResponse.count
                Write-Verbose "[$Me]: Count retrieved successfully: $Count"
                return $Count
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Type = "APIError"
                $ErrorObject.Code = $Response.ServiceResponse.responseCode

                if ($Response.ServiceResponse.responseErrorDetails) {
                    $ErrorObject.Note = $Response.ServiceResponse.responseErrorDetails.errorMessage
                } else {
                    $ErrorObject.Note = "Qualys API returned an error"
                }

                $ErrorObject.Raw = $Response
                return $ErrorObject
            }
        } catch {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "Exception"
            $ErrorObject.Note = $_.Exception.Message
            $ErrorObject.Raw = $_

            if ($_.Exception.Response.StatusCode.value__) {
                $ErrorObject.Code = $_.Exception.Response.StatusCode.value__
                Write-Verbose "[$Me]: HTTP Code: $($ErrorObject.Code)"
            }

            return $ErrorObject
        }
    }

    End { }
}
