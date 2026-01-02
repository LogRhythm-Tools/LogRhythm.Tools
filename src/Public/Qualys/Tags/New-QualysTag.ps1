using namespace System
using namespace System.Collections.Generic

Function New-QualysTag {
    <#
    .SYNOPSIS
        Create a new Qualys tag.
    .DESCRIPTION
        Creates a new tag and optionally child tags in Qualys.

        Supports creating static tags, dynamic tags with various rule types, and tags with child tags.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Name
        Name of the tag to create.
    .PARAMETER Color
        Tag color in hex format (e.g., #FFFFFF). Defaults to #FFFFFF.
    .PARAMETER CriticalityScore
        Asset criticality score for the tag (1-5, where 5 is highest).
    .PARAMETER RuleType
        Type of rule for dynamic tags.

        Valid values: STATIC, GROOVY, OS_REGEX, NETWORK_RANGE, NAME_CONTAINS, INSTALLED_SOFTWARE,
        OPEN_PORTS, VULN_EXIST, ASSET_SEARCH, CLOUD_ASSET, BUSINESS_INFORMATION, GLOBAL_ASSET_VIEW,
        NETWORK_RANGE_ENHANCED, TAG_SET
    .PARAMETER RuleText
        The rule definition text for dynamic tags. Required when RuleType is specified.

        The format varies by RuleType:

        GROOVY:
            Groovy script code (e.g., "if(asset.getAssetType()!=Asset.AssetType.HOST) return false;")

        GLOBAL_ASSET_VIEW:
            Query syntax (e.g., "operatingSystem.lifecycle.stage:`EOL`")

        OS_REGEX:
            Regular expression pattern to match OS names

        NETWORK_RANGE:
            IP ranges (e.g., "10.0.0.0-10.0.0.255")

        NAME_CONTAINS:
            String to match in asset names

        INSTALLED_SOFTWARE:
            Software name to match

        OPEN_PORTS:
            Port numbers or ranges

        VULN_EXIST:
            Vulnerability QIDs

        ASSET_SEARCH:
            XML-formatted search criteria (complex, see Qualys API docs)

        CLOUD_ASSET:
            Cloud-specific query syntax

        TAG_SET:
            XML CDATA containing tag set rules (complex, see Qualys API docs)
    .PARAMETER Provider
        Cloud provider name. Required for CLOUD_ASSET rule type.

        Valid values: EC2, AZURE, GCP, IBM, OCI, Alibaba
    .PARAMETER ChildTags
        Array of child tag names to create under this parent tag.
    .OUTPUTS
        PSCustomObject representing the created Qualys Tag object.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Production Servers" -Color "#FF0000"

        Creates a simple static tag with red color.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Critical Assets" -CriticalityScore 5 -Color "#FF0000"

        Creates a tag with criticality score of 5.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Parent Tag" -ChildTags @("Child 1", "Child 2", "Child 3")

        Creates a parent tag with three child tags.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "EOL Systems" -RuleType "GLOBAL_ASSET_VIEW" -RuleText "operatingSystem.lifecycle.stage:`EOL`"

        Creates a dynamic tag using GLOBAL_ASSET_VIEW rule to find end-of-life systems.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Linux Servers" -RuleType "GLOBAL_ASSET_VIEW" -RuleText "operatingSystem.name:`"Linux`""

        Creates a dynamic tag to match Linux operating systems.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Azure VMs" -RuleType "CLOUD_ASSET" -Provider "AZURE" -RuleText "cloud.provider:azure"

        Creates a cloud asset tag for Azure resources.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Critical Vulns" -RuleType "GROOVY" -RuleText "if(asset.getAssetType()!=Asset.AssetType.HOST) return false; return asset.hasVulnsWithSeverity(4,5)"

        Creates a Groovy-based dynamic tag to match assets with severity 4 or 5 vulnerabilities.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Windows OS" -RuleType "OS_REGEX" -RuleText ".*Windows.*"

        Creates a tag using regex to match any Windows operating system.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Private Network" -RuleType "NETWORK_RANGE" -RuleText "10.0.0.0-10.255.255.255"

        Creates a tag for assets in the 10.x.x.x private network range.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Web Servers" -RuleType "NAME_CONTAINS" -RuleText "web"

        Creates a tag matching assets with "web" in their name.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Has Chrome" -RuleType "INSTALLED_SOFTWARE" -RuleText "Google Chrome"

        Creates a tag for assets with Google Chrome installed.
    .EXAMPLE
        PS C:\> New-QualysTag -Name "Open SSH" -RuleType "OPEN_PORTS" -RuleText "22"

        Creates a tag for assets with port 22 open.
    .NOTES
        Qualys-API v2.0
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidatePattern('^#[0-9A-Fa-f]{6}$')]
        [string] $Color = "#FFFFFF",

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateRange(1, 5)]
        [int] $CriticalityScore,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateSet('STATIC', 'GROOVY', 'OS_REGEX', 'NETWORK_RANGE', 'NAME_CONTAINS', 'INSTALLED_SOFTWARE',
                     'OPEN_PORTS', 'VULN_EXIST', 'ASSET_SEARCH', 'CLOUD_ASSET', 'BUSINESS_INFORMATION',
                     'GLOBAL_ASSET_VIEW', 'NETWORK_RANGE_ENHANCED', 'TAG_SET', ignorecase=$true)]
        [string] $RuleType,

        [Parameter(Mandatory = $false, Position = 4)]
        [string] $RuleText,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('EC2', 'AZURE', 'GCP', 'IBM', 'OCI', 'Alibaba', ignorecase=$true)]
        [string] $Provider,

        [Parameter(Mandatory = $false, Position = 6)]
        [string[]] $ChildTags,

        [Parameter(Mandatory = $false, Position = 7)]
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
            Value = $Name
            Raw   = $null
        }

        # Validate RuleType and RuleText dependencies
        if ($RuleType -and -not $RuleText) {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "ValidationError"
            $ErrorObject.Note = "RuleText is required when RuleType is specified"
            return $ErrorObject
        }

        if ($RuleType -eq 'CLOUD_ASSET' -and -not $Provider) {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "ValidationError"
            $ErrorObject.Note = "Provider is required when RuleType is CLOUD_ASSET"
            return $ErrorObject
        }

        # Build XML Request Body
        $XmlBuilder = [System.Text.StringBuilder]::new()
        [void]$XmlBuilder.AppendLine('<?xml version="1.0" encoding="UTF-8" ?>')
        [void]$XmlBuilder.AppendLine('<ServiceRequest>')
        [void]$XmlBuilder.AppendLine('    <data>')
        [void]$XmlBuilder.AppendLine('        <Tag>')

        # Tag Name
        $EncodedName = [System.Security.SecurityElement]::Escape($Name)
        [void]$XmlBuilder.AppendLine("            <name>$EncodedName</name>")

        # Color
        if ($Color) {
            $EncodedColor = [System.Security.SecurityElement]::Escape($Color)
            [void]$XmlBuilder.AppendLine("            <color>$EncodedColor</color>")
        }

        # Criticality Score
        if ($CriticalityScore) {
            [void]$XmlBuilder.AppendLine("            <criticalityScore>$CriticalityScore</criticalityScore>")
        }

        # Rule Type
        if ($RuleType) {
            [void]$XmlBuilder.AppendLine("            <ruleType>$RuleType</ruleType>")
        }

        # Rule Text
        if ($RuleText) {
            $EncodedRuleText = [System.Security.SecurityElement]::Escape($RuleText)
            [void]$XmlBuilder.AppendLine("            <ruleText>$EncodedRuleText</ruleText>")
        }

        # Provider (for cloud assets)
        if ($Provider) {
            [void]$XmlBuilder.AppendLine("            <provider>$Provider</provider>")
        }

        # Child Tags
        if ($ChildTags -and $ChildTags.Count -gt 0) {
            [void]$XmlBuilder.AppendLine('            <children>')
            [void]$XmlBuilder.AppendLine('                <set>')
            foreach ($ChildTag in $ChildTags) {
                $EncodedChildName = [System.Security.SecurityElement]::Escape($ChildTag)
                [void]$XmlBuilder.AppendLine('                    <TagSimple>')
                [void]$XmlBuilder.AppendLine("                        <name>$EncodedChildName</name>")
                [void]$XmlBuilder.AppendLine('                    </TagSimple>')
            }
            [void]$XmlBuilder.AppendLine('                </set>')
            [void]$XmlBuilder.AppendLine('            </children>')
        }

        [void]$XmlBuilder.AppendLine('        </Tag>')
        [void]$XmlBuilder.AppendLine('    </data>')
        [void]$XmlBuilder.AppendLine('</ServiceRequest>')

        $RequestBody = $XmlBuilder.ToString()
        Write-Verbose "[$Me]: Request Body:`n$RequestBody"

        # Define URL
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/create/am/tag"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers -Body $RequestBody

            # Parse XML response
            if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                $Tag = $Response.ServiceResponse.data.Tag
                Write-Verbose "[$Me]: Tag created successfully. ID: $($Tag.id)"
                return $Tag
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
