using namespace System
using namespace System.Collections.Generic

Function Get-QualysHostAssets {
    <#
    .SYNOPSIS
        Search for Qualys host assets.
    .DESCRIPTION
        Returns a list of host assets matching the provided criteria. Assets are returned
        when they are visible to the user (i.e. in the user's scope).

        A maximum of 100 host assets are returned by default. Pagination is automatically
        handled to retrieve all matching assets.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        Filter by host asset ID.
    .PARAMETER Name
        Filter by asset name (supports partial matches).
    .PARAMETER DnsHostName
        Filter by DNS hostname.
    .PARAMETER Address
        Filter by IP address.
    .PARAMETER Os
        Filter by operating system.
    .PARAMETER TagName
        Filter by tag name.
    .PARAMETER TagId
        Filter by tag ID.
    .PARAMETER TrackingMethod
        Filter by tracking method.

        Valid values: NONE, IP, DNSNAME, NETBIOS, INSTANCE_ID, QAGENT, EC2_INSTANCE_ID,
        GCP_INSTANCE_ID, VIRTUAL_MACHINE_ID, etc.
    .PARAMETER CustomFilters
        Hashtable of custom filter criteria for advanced searches.
        Example: @{field="qwebHostId"; operator="EQUALS"; value="12345"}
    .OUTPUTS
        Array of PSCustomObject representing Qualys HostAsset objects.
    .EXAMPLE
        PS C:\> Get-QualysHostAssets

        Returns all host assets visible to the user.
    .EXAMPLE
        PS C:\> Get-QualysHostAssets -Name "web"

        Returns all host assets with "web" in the name.
    .EXAMPLE
        PS C:\> Get-QualysHostAssets -Address "10.0.0.1"

        Returns host assets with the specified IP address.
    .EXAMPLE
        PS C:\> Get-QualysHostAssets -TagName "Production"

        Returns all host assets tagged with "Production".
    .EXAMPLE
        PS C:\> Get-QualysHostAssets -Os "Windows" -TagId 12345

        Returns Windows hosts with specific tag ID.
    .NOTES
        Qualys-API v2.0

        Permissions required: Managers with full scope, other users must have Access
        Permission "API Access" and Asset Management Permission "Read Asset"
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
        [string] $DnsHostName,

        [Parameter(Mandatory = $false, Position = 3)]
        [string] $Address,

        [Parameter(Mandatory = $false, Position = 4)]
        [string] $Os,

        [Parameter(Mandatory = $false, Position = 5)]
        [string] $TagName,

        [Parameter(Mandatory = $false, Position = 6)]
        [int] $TagId,

        [Parameter(Mandatory = $false, Position = 7)]
        [string] $TrackingMethod,

        [Parameter(Mandatory = $false, Position = 8)]
        [hashtable[]] $CustomFilters,

        [Parameter(Mandatory = $false, Position = 9)]
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
        $AllAssets = @()
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
        if ($Id -or $Name -or $DnsHostName -or $Address -or $Os -or $TagName -or $TagId -or $TrackingMethod -or $CustomFilters) {
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

        if ($DnsHostName) {
            $EncodedDns = [System.Security.SecurityElement]::Escape($DnsHostName)
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"dnsHostName`" operator=`"CONTAINS`">$EncodedDns</Criteria>")
        }

        if ($Address) {
            $EncodedAddress = [System.Security.SecurityElement]::Escape($Address)
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"address`" operator=`"EQUALS`">$EncodedAddress</Criteria>")
        }

        if ($Os) {
            $EncodedOs = [System.Security.SecurityElement]::Escape($Os)
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"os`" operator=`"CONTAINS`">$EncodedOs</Criteria>")
        }

        if ($TagName) {
            $EncodedTagName = [System.Security.SecurityElement]::Escape($TagName)
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"tagName`" operator=`"CONTAINS`">$EncodedTagName</Criteria>")
        }

        if ($TagId) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"tagId`" operator=`"EQUALS`">$TagId</Criteria>")
        }

        if ($TrackingMethod) {
            [void]$XmlBuilder.AppendLine("        <Criteria field=`"trackingMethod`" operator=`"EQUALS`">$TrackingMethod</Criteria>")
        }

        # Custom filters
        if ($CustomFilters) {
            foreach ($Filter in $CustomFilters) {
                $FilterField = $Filter.field
                $FilterOperator = if ($Filter.operator) { $Filter.operator } else { "EQUALS" }
                $FilterValue = [System.Security.SecurityElement]::Escape($Filter.value)
                [void]$XmlBuilder.AppendLine("        <Criteria field=`"$FilterField`" operator=`"$FilterOperator`">$FilterValue</Criteria>")
            }
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
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/search/am/hostasset"
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
                    $Assets = $Response.ServiceResponse.data.HostAsset
                    $Count = [int]$Response.ServiceResponse.count
                    $HasMoreRecords = $Response.ServiceResponse.hasMoreRecords -eq "true"

                    Write-Verbose "[$Me]: Retrieved $Count assets. HasMoreRecords: $HasMoreRecords"

                    # Add assets to collection
                    if ($Assets) {
                        if ($Assets -is [System.Array]) {
                            $AllAssets += $Assets
                        } else {
                            # Single asset returned
                            $AllAssets += $Assets
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
        if ($AllAssets.Count -gt 0) {
            return $AllAssets
        } else {
            Write-Verbose "[$Me]: No host assets found matching the criteria"
            return $null
        }
    }

    End { }
}
