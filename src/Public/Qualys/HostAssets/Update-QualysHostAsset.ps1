using namespace System
using namespace System.Collections.Generic

Function Update-QualysHostAsset {
    <#
    .SYNOPSIS
        Update a Qualys host asset.
    .DESCRIPTION
        Updates fields for a host asset, including adding or removing tags.

        NOTE: Only static tags can be added/removed. Dynamic tags are managed automatically
        by Qualys based on tag rules.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        Host asset ID to update.
    .PARAMETER Name
        New name for the host asset.
    .PARAMETER AddTagIds
        Array of tag IDs to add to this host asset (static tags only).
    .PARAMETER RemoveTagIds
        Array of tag IDs to remove from this host asset (static tags only).
    .OUTPUTS
        PSCustomObject representing the updated host asset ID or an error object.
    .EXAMPLE
        PS C:\> Update-QualysHostAsset -Id 12345 -Name "Updated Server Name"

        Updates the host asset name.
    .EXAMPLE
        PS C:\> Update-QualysHostAsset -Id 12345 -AddTagIds @(111, 222)

        Adds tags with IDs 111 and 222 to the host asset.
    .EXAMPLE
        PS C:\> Update-QualysHostAsset -Id 12345 -RemoveTagIds @(333)

        Removes tag with ID 333 from the host asset.
    .EXAMPLE
        PS C:\> Update-QualysHostAsset -Id 12345 -AddTagIds @(111) -RemoveTagIds @(222)

        Adds one tag and removes another in a single operation.
    .EXAMPLE
        PS C:\> Get-QualysHostAssets -Name "webserver" | ForEach-Object {
            Update-QualysHostAsset -Id $_.id -AddTagIds @(999)
        }

        Pipeline example: Find all webservers and add a tag to each.
    .NOTES
        Qualys-API v2.0

        Permissions required: Managers with full scope, other users must have the requested
        assets in their scope and these permissions: Access Permission "API Access" and
        Asset Management Permission "Update Asset"

        Important: Only static tags can be added/removed. Dynamic tags cannot be manually
        managed and will be declined in the API request.
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
        [int[]] $AddTagIds,

        [Parameter(Mandatory = $false, Position = 3)]
        [int[]] $RemoveTagIds,

        [Parameter(Mandatory = $false, Position = 4)]
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
        if (-not ($Name -or $AddTagIds -or $RemoveTagIds)) {
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
        [void]$XmlBuilder.AppendLine('        <HostAsset>')

        # Asset Name
        if ($Name) {
            $EncodedName = [System.Security.SecurityElement]::Escape($Name)
            [void]$XmlBuilder.AppendLine("            <name>$EncodedName</name>")
        }

        # Tags
        if ($AddTagIds -or $RemoveTagIds) {
            [void]$XmlBuilder.AppendLine('            <tags>')

            # Add tags
            if ($AddTagIds -and $AddTagIds.Count -gt 0) {
                [void]$XmlBuilder.AppendLine('                <add>')
                foreach ($TagId in $AddTagIds) {
                    [void]$XmlBuilder.AppendLine('                    <TagSimple>')
                    [void]$XmlBuilder.AppendLine("                        <id>$TagId</id>")
                    [void]$XmlBuilder.AppendLine('                    </TagSimple>')
                }
                [void]$XmlBuilder.AppendLine('                </add>')
            }

            # Remove tags
            if ($RemoveTagIds -and $RemoveTagIds.Count -gt 0) {
                [void]$XmlBuilder.AppendLine('                <remove>')
                foreach ($TagId in $RemoveTagIds) {
                    [void]$XmlBuilder.AppendLine('                    <TagSimple>')
                    [void]$XmlBuilder.AppendLine("                        <id>$TagId</id>")
                    [void]$XmlBuilder.AppendLine('                    </TagSimple>')
                }
                [void]$XmlBuilder.AppendLine('                </remove>')
            }

            [void]$XmlBuilder.AppendLine('            </tags>')
        }

        [void]$XmlBuilder.AppendLine('        </HostAsset>')
        [void]$XmlBuilder.AppendLine('    </data>')
        [void]$XmlBuilder.AppendLine('</ServiceRequest>')

        $RequestBody = $XmlBuilder.ToString()
        Write-Verbose "[$Me]: Request Body:`n$RequestBody"

        # Define URL
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/update/am/hostasset/$Id"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers -Body $RequestBody

            # Parse XML response
            if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                $UpdatedAsset = $Response.ServiceResponse.data.HostAsset
                Write-Verbose "[$Me]: Host asset updated successfully. ID: $($UpdatedAsset.id)"
                return $UpdatedAsset
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
