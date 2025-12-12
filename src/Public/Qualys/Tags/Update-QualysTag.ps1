using namespace System
using namespace System.Collections.Generic

Function Update-QualysTag {
    <#
    .SYNOPSIS
        Update a Qualys tag.
    .DESCRIPTION
        Updates fields for a tag, including name, color, criticality score, rule type/text,
        and child tags.

        Note: Provider name cannot be updated after tag creation.
        Using the NOT EQUALS operator for updating tags could result in accidental updates
        of unknown tags. NOT EQUALS operator is not supported for update actions.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        Tag ID to update.
    .PARAMETER Name
        New name for the tag.
    .PARAMETER Color
        New tag color in hex format (e.g., #FFFFFF).
    .PARAMETER CriticalityScore
        New asset criticality score for the tag (1-5, where 5 is highest).
    .PARAMETER RuleType
        New rule type for dynamic tags.

        Valid values: STATIC, GROOVY, OS_REGEX, NETWORK_RANGE, NAME_CONTAINS, INSTALLED_SOFTWARE,
        OPEN_PORTS, VULN_EXIST, ASSET_SEARCH, CLOUD_ASSET, BUSINESS_INFORMATION, GLOBAL_ASSET_VIEW,
        NETWORK_RANGE_ENHANCED, TAG_SET
    .PARAMETER RuleText
        New rule definition text for dynamic tags.

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

        See docs/QualysRuleTextGuide.md for detailed examples and guidance.
    .PARAMETER AddChildTags
        Array of child tag names to add to this parent tag.
    .PARAMETER RemoveChildTagIds
        Array of child tag IDs to remove from this parent tag.
    .OUTPUTS
        PSCustomObject representing the updated tag ID or an error object.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -Name "Updated Tag Name"

        Updates the tag name.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -CriticalityScore 5 -Color "#FF0000"

        Updates criticality score to highest (5) and changes color to red.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -Name "Updated" -AddChildTags @("Child") -RemoveChildTagIds @(999)

        Updates name, adds a child tag, and removes another child tag in a single operation.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -AddChildTags @("New Child 1", "New Child 2")

        Adds new child tags to the parent.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -RemoveChildTagIds @(123, 456)

        Removes multiple child tags by their IDs.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -RuleType "GLOBAL_ASSET_VIEW" -RuleText "operatingSystem.lifecycle.stage:`EOL`"

        Updates tag to use GLOBAL_ASSET_VIEW rule for end-of-life systems.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -RuleType "NAME_CONTAINS" -RuleText "production"

        Changes tag to a NAME_CONTAINS rule matching assets with "production" in the name.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -RuleType "NETWORK_RANGE" -RuleText "192.168.1.0/24"

        Updates tag to match a specific network range.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -RuleType "GROOVY" -RuleText "return asset.hasVulnsWithSeverity(5)"

        Updates to a Groovy rule for assets with severity 5 vulnerabilities.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -RuleType "OPEN_PORTS" -RuleText "80,443,8080"

        Updates tag to match assets with specific open ports.
    .EXAMPLE
        PS C:\> Get-QualysTags -Name "Old Name" -Exact | Update-QualysTag -Name "New Name" -CriticalityScore 4

        Pipeline example: Find a tag by exact name and update it.
    .EXAMPLE
        PS C:\> Update-QualysTag -Id 12345 -Color "#00FF00"

        Updates only the tag color to green, leaving all other properties unchanged.
    .NOTES
        Qualys-API v2.0

        Permissions required: Managers with full scope, other users must have these permissions:
        Access Permission "API Access", Tag Permission "Create User Tag", Tag Permission
        "Modify Dynamic Tag Rules" (to create a dynamic tag)

        Important Notes:
        - Provider name cannot be updated after tag creation
        - Only specify the parameters you want to update; others remain unchanged
        - See docs/QualysRuleTextGuide.md for detailed RuleText format guidance
        - Use -Verbose to see the exact XML being sent to Qualys
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [int] $Id,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Name,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidatePattern('^#[0-9A-Fa-f]{6}$')]
        [string] $Color,

        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateRange(1, 5)]
        [int] $CriticalityScore,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('STATIC', 'GROOVY', 'OS_REGEX', 'NETWORK_RANGE', 'NAME_CONTAINS', 'INSTALLED_SOFTWARE',
                     'OPEN_PORTS', 'VULN_EXIST', 'ASSET_SEARCH', 'CLOUD_ASSET', 'BUSINESS_INFORMATION',
                     'GLOBAL_ASSET_VIEW', 'NETWORK_RANGE_ENHANCED', 'TAG_SET', ignorecase=$true)]
        [string] $RuleType,

        [Parameter(Mandatory = $false, Position = 5)]
        [string] $RuleText,

        [Parameter(Mandatory = $false, Position = 6)]
        [string[]] $AddChildTags,

        [Parameter(Mandatory = $false, Position = 7)]
        [int[]] $RemoveChildTagIds,

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
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code  = $null
            Error = $false
            Type  = $null
            Note  = $null
            Value = $Id
            Raw   = $null
        }

        # Validate that at least one update parameter is provided
        if (-not ($Name -or $Color -or $CriticalityScore -or $RuleType -or $RuleText -or $AddChildTags -or $RemoveChildTagIds)) {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "ValidationError"
            $ErrorObject.Note = "At least one update parameter must be specified"
            return $ErrorObject
        }

        # Build XML Request Body
        $XmlBuilder = [System.Text.StringBuilder]::new()
        [void]$XmlBuilder.AppendLine('<?xml version="1.0" encoding="UTF-8" ?>')
        [void]$XmlBuilder.AppendLine('<ServiceRequest>')
        [void]$XmlBuilder.AppendLine('    <data>')
        [void]$XmlBuilder.AppendLine('        <Tag>')

        # Tag Name
        if ($Name) {
            $EncodedName = [System.Security.SecurityElement]::Escape($Name)
            [void]$XmlBuilder.AppendLine("            <name>$EncodedName</name>")
        }

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

        # Child Tags
        if ($AddChildTags -or $RemoveChildTagIds) {
            [void]$XmlBuilder.AppendLine('            <children>')

            # Add child tags
            if ($AddChildTags -and $AddChildTags.Count -gt 0) {
                [void]$XmlBuilder.AppendLine('                <set>')
                foreach ($ChildTag in $AddChildTags) {
                    $EncodedChildName = [System.Security.SecurityElement]::Escape($ChildTag)
                    [void]$XmlBuilder.AppendLine('                    <TagSimple>')
                    [void]$XmlBuilder.AppendLine("                        <name>$EncodedChildName</name>")
                    [void]$XmlBuilder.AppendLine('                    </TagSimple>')
                }
                [void]$XmlBuilder.AppendLine('                </set>')
            }

            # Remove child tags
            if ($RemoveChildTagIds -and $RemoveChildTagIds.Count -gt 0) {
                [void]$XmlBuilder.AppendLine('                <remove>')
                foreach ($ChildId in $RemoveChildTagIds) {
                    [void]$XmlBuilder.AppendLine('                    <TagSimple>')
                    [void]$XmlBuilder.AppendLine("                        <id>$ChildId</id>")
                    [void]$XmlBuilder.AppendLine('                    </TagSimple>')
                }
                [void]$XmlBuilder.AppendLine('                </remove>')
            }

            [void]$XmlBuilder.AppendLine('            </children>')
        }

        [void]$XmlBuilder.AppendLine('        </Tag>')
        [void]$XmlBuilder.AppendLine('    </data>')
        [void]$XmlBuilder.AppendLine('</ServiceRequest>')

        $RequestBody = $XmlBuilder.ToString()
        Write-Verbose "[$Me]: Request Body:`n$RequestBody"

        # Define URL
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/update/am/tag/$Id"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers -Body $RequestBody

            # Parse XML response
            if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                $UpdatedTag = $Response.ServiceResponse.data.Tag
                Write-Verbose "[$Me]: Tag updated successfully. ID: $($UpdatedTag.id)"
                return $UpdatedTag
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
