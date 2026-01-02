using namespace System
using namespace System.Collections.Generic

Function Remove-QualysTag {
    <#
    .SYNOPSIS
        Delete a Qualys tag.
    .DESCRIPTION
        Deletes one or more tags from Qualys by tag ID.

        Note: Using the NOT EQUALS operator for deleting tags could result in accidental
        deletion of unknown tags without any warning. To prevent accidental deletion,
        NOT EQUALS operator is not supported for delete actions.
    .PARAMETER Credential
        PSCredential containing Qualys username and password.
    .PARAMETER Id
        Tag ID(s) to delete. Accepts a single ID or an array of IDs.
    .PARAMETER Force
        Bypasses confirmation prompts.
    .OUTPUTS
        PSCustomObject representing the deleted tag ID(s) or an error object.
    .EXAMPLE
        PS C:\> Remove-QualysTag -Id 12345

        Deletes the tag with ID 12345 (with confirmation prompt).
    .EXAMPLE
        PS C:\> Remove-QualysTag -Id 12345 -Force

        Deletes the tag with ID 12345 without confirmation.
    .EXAMPLE
        PS C:\> Remove-QualysTag -Id 12345,67890 -Force

        Deletes multiple tags by ID.
    .EXAMPLE
        PS C:\> Get-QualysTags -Name "TestTag" | ForEach-Object { Remove-QualysTag -Id $_.id -Force }

        Finds and deletes all tags matching "TestTag".
    .NOTES
        Qualys-API v2.0

        Permissions required: Managers with full scope, other users must have Access
        Permission "API Access" and Tag Permission "Delete User Tag"
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [int[]] $Id,

        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $Force,

        [Parameter(Mandatory = $false, Position = 2)]
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

        # Results collection
        $Results = @()
    }

    Process {
        foreach ($TagId in $Id) {
            # Establish General Error object Output
            $ErrorObject = [PSCustomObject]@{
                Code  = $null
                Error = $false
                Type  = $null
                Note  = $null
                Value = $TagId
                Raw   = $null
            }

            # Confirmation prompt
            if ($Force -or $PSCmdlet.ShouldProcess("Tag ID: $TagId", "Delete Qualys Tag")) {

                # Define URL
                $RequestUrl = $BaseUrl.TrimEnd('/') + "/qps/rest/2.0/delete/am/tag/$TagId"
                Write-Verbose "[$Me]: Request URL: $RequestUrl"

                Try {
                    $Response = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers

                    # Parse XML response
                    if ($Response.ServiceResponse.responseCode -eq "SUCCESS") {
                        $DeletedTag = $Response.ServiceResponse.data.SimpleTag
                        Write-Verbose "[$Me]: Tag deleted successfully. ID: $($DeletedTag.id)"
                        $Results += $DeletedTag
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
                        $Results += $ErrorObject
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

                    $Results += $ErrorObject
                }
            } else {
                Write-Verbose "[$Me]: Deletion cancelled by user for Tag ID: $TagId"
            }
        }
    }

    End {
        return $Results
    }
}
