using namespace System
using namespace System.Collections.Generic

Function Get-QualysTags {
    <#
    .SYNOPSIS
        Get Qualys Tags.
    .DESCRIPTION
        Returns a list of tags from Qualys that match the provided criteria.

        A maximum of 100 tags are returned by default. Pagination is automatically
        handled to retrieve all matching tags.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        Filter by tag ID.
    .PARAMETER Name
        Filter by tag name (supports partial matches).
    .PARAMETER Parent
        Filter by parent tag ID.
    .PARAMETER RuleType
        Filter by rule type.

        Valid values: GROOVY, OS_REGEX, NETWORK_RANGE, NAME_CONTAINS, INSTALLED_SOFTWARE,
        OPEN_PORTS, VULN_EXIST, ASSET_SEARCH, CLOUD_ASSET, BUSINESS_INFORMATION
    .PARAMETER Provider
        Filter by cloud provider.

        Valid values: EC2, AZURE, GCP, IBM, OCI, Alibaba
    .PARAMETER Color
        Filter by tag color (hex format: #FFFFFF).
    .PARAMETER CriticalityScore
        Filter by criticality score.
    .PARAMETER Exact
        Return only exact matches for the Name parameter.
    .OUTPUTS
        PSCustomObject representing Qualys Tag objects.
    .EXAMPLE
        PS C:\> Get-QualysTags

        Returns all tags from Qualys.
    .EXAMPLE
        PS C:\> Get-QualysTags -Name "Production"

        Returns all tags with "Production" in the name.
    .EXAMPLE
        PS C:\> Get-QualysTags -Name "Production" -Exact

        Returns only the tag with the exact name "Production".
    .EXAMPLE
        PS C:\> Get-QualysTags -CriticalityScore 3

        Returns all tags with criticality score of 3.
    .EXAMPLE
        PS C:\> Get-QualysTags -RuleType "CLOUD_ASSET" -Provider "AZURE"

        Returns all Azure cloud asset tags.
    .NOTES
        Qualys-API v2.0
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
        [ValidateSet('GROOVY', 'OS_REGEX', 'NETWORK_RANGE', 'NAME_CONTAINS', 'INSTALLED_SOFTWARE',
                     'OPEN_PORTS', 'VULN_EXIST', 'ASSET_SEARCH', 'CLOUD_ASSET', 'BUSINESS_INFORMATION',
                     ignorecase=$true)]
        [string] $RuleType,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('EC2', 'AZURE', 'GCP', 'IBM', 'OCI', 'Alibaba', ignorecase=$true)]
        [string] $Provider,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidatePattern('^#[0-9A-Fa-f]{6}$')]
        [string] $Color,

        [Parameter(Mandatory = $false, Position = 6)]
        [int] $CriticalityScore,

        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $Exact,

        [Parameter(Mandatory = $false, Position = 8)]
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

        # Pagination settings
        $PageSize = 100
        $Offset = 1
        $AllTags = @()
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
        if ($Id -or $Name -or $Parent -or $RuleType -or $Provider -or $Color -or $CriticalityScore) {
            [void]$XmlBuilder.AppendLine('    <filters>')
            $HasFilters = $true
        }

        if ($Id) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"id`" operator=`"EQUALS`">$Id</Criteria>")
        }

        if ($Name) {
            $Operator = if ($Exact) { "EQUALS" } else { "CONTAINS" }
            $EncodedName = [System.Security.SecurityElement]::Escape($Name)
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"name`" operator=`"$Operator`">$EncodedName</Criteria>")
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

        if ($CriticalityScore) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"criticalityScore`" operator=`"EQUALS`">$CriticalityScore</Criteria>")
        }

        if ($HasFilters) {
            [void]$XmlBuilder.AppendLine('    </filters>')
        }

        # Add pagination preferences
        [void]$XmlBuilder.AppendLine('    <preferences>')
        [void]$XmlBuilder.AppendLine("        <limitResults>$PageSize</limitResults>")
        [void]$XmlBuilder.AppendLine("        <startFromOffset>$Offset</startFromOffset>")
        [void]$XmlBuilder.AppendLine('    </preferences>')

        [void]$XmlBuilder.AppendLine('</ServiceRequest>')

        $RequestBody = $XmlBuilder.ToString()
        Write-Verbose "[$Me]: Request Body:`n$RequestBody"

        # Define Search URL
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/search/am/tag"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Pagination loop
        Do {
            # Update offset in XML body for subsequent requests
            if ($Offset -gt 1) {
                $RequestBody = $RequestBody -replace '<startFromOffset>\d+</startFromOffset>', "<startFromOffset>$Offset</startFromOffset>"
                Write-Verbose "[$Me]: Pagination - Offset: $Offset"
            }

            Try {
                $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers -Body $RequestBody

                # Parse XML response
                if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                    $Tags = $Response.ServiceResponse.data.Tag
                    $Count = [int]$Response.ServiceResponse.count
                    $HasMoreRecords = $Response.ServiceResponse.hasMoreRecords -eq "true"

                    Write-Verbose "[$Me]: Retrieved $Count tags. HasMoreRecords: $HasMoreRecords"

                    # Add tags to collection
                    if ($Tags) {
                        if ($Tags -is [System.Array]) {
                            $AllTags += $Tags
                        } else {
                            # Single tag returned
                            $AllTags += $Tags
                        }
                    }

                    # Update offset for next page
                    $Offset += $PageSize
                } else {
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "APIError"
                    $ErrorObject.Code = $Response.ServiceResponse.responseCode
                    $ErrorObject.Note = "Qualys API returned an error"
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
        } While ($HasMoreRecords)

        # Return results
        if ($AllTags.Count -gt 0) {
            return $AllTags
        } else {
            Write-Verbose "[$Me]: No tags found matching the criteria"
            return $null
        }
    }

    End { }
}
