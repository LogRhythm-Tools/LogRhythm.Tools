using namespace System
using namespace System.Collections.Generic

Function Get-QualysHostAsset {
    <#
    .SYNOPSIS
        Get a single Qualys host asset by ID.
    .DESCRIPTION
        Returns detailed information about a specific host asset by its ID.

        Use Get-QualysHostAssets (plural) to search for multiple assets by various criteria.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        The host asset ID to retrieve.
    .OUTPUTS
        PSCustomObject representing the Qualys HostAsset object with full details.
    .EXAMPLE
        PS C:\> Get-QualysHostAsset -Id 12345

        Returns detailed information about host asset with ID 12345.
    .EXAMPLE
        PS C:\> Get-QualysHostAssets -Name "web01" | Select-Object -First 1 -ExpandProperty id | Get-QualysHostAsset

        Search for an asset by name and get its full details.
    .NOTES
        Qualys-API v2.0

        Permissions required: Managers with full scope. Other users must have requested
        asset in their scope and these permissions: Access Permission "API Access" and
        Asset Management Permission "Read Asset"
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [int] $Id,

        [Parameter(Mandatory = $false, Position = 1)]
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

        # Define HTTP Method
        $Method = $HttpMethod.Get

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

        # Define URL
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/get/am/hostasset/$Id"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers

            # Parse XML response
            if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                $Asset = $Response.ServiceResponse.data.HostAsset
                Write-Verbose "[$Me]: Host asset retrieved successfully. ID: $($Asset.id), Name: $($Asset.name)"
                return $Asset
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
