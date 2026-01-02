using namespace System
using namespace System.Collections.Generic

Function Get-QualysTag {
    <#
    .SYNOPSIS
        Get a single Qualys tag by ID.
    .DESCRIPTION
        Returns detailed information about a specific tag by its ID.

        Use Get-QualysTags (plural) to search for multiple tags by various criteria.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        The tag ID to retrieve.
    .OUTPUTS
        PSCustomObject representing the Qualys Tag object with full details.
    .EXAMPLE
        PS C:\> Get-QualysTag -Id 12345

        Returns detailed information about tag with ID 12345.
    .EXAMPLE
        PS C:\> Get-QualysTags -Name "Production" | Select-Object -First 1 -ExpandProperty id | Get-QualysTag

        Search for a tag by name and get its full details.
    .NOTES
        Qualys-API v2.0

        Permissions required: Managers with full scope, other users must have
        Access Permission "API Access"
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
        $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/get/am/tag/$Id"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers

            # Parse XML response
            if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                $Tag = $Response.ServiceResponse.data.Tag
                Write-Verbose "[$Me]: Tag retrieved successfully. ID: $($Tag.id), Name: $($Tag.name)"
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
