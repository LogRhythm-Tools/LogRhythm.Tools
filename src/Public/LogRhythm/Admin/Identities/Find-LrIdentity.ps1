using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Find-LrIdentity {
    <#
    .SYNOPSIS
        Retrieve a list of Identities from TrueIdentity based TrueIdentity ID.
    .DESCRIPTION
        Find-LrIdentity returns a full LogRhythm List object, including it's details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        Int32 value that represents a TrueIdentity ID record.

        Supports an array of TrueIdentity ID values.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        Find-LrIdentity -Id 7
        ---
        identityID        : 7
        nameFirst         : Eric
        nameMiddle        :
        nameLast          : Hart
        displayIdentifier : Eric.Hart
        company           : LogRhythm Inc.
        department        : Customer Success
        title             :
        manager           :
        addressCity       :
        domainName        :
        entity            : @{entityId=1; rootEntityId=0; path=Primary Site; name=Primary Site}
        dateUpdated       : 2020-06-19T13:37:28.86Z
        recordStatus      : Active
        identifiers       : {@{identifierID=4; identifierType=Login; value=eric.hart@logrhythm.com; recordStatus=Active; source=}, @{identifierID=5; identifierType=Email;        
                            value=eric.hart@logrhythm.com; recordStatus=Active; source=}}
        groups            : {@{name=Domain Admins}}
    .EXAMPLE
        Find-LrIdentity -Id @(1, 3, 7, 12)
        ---

        identityID        : 1
        nameFirst         : Eric
        nameMiddle        : W
        nameLast          : Hart
        displayIdentifier : Eric.Hart
        company           : LogRhythm
        department        : Customer Success
        title             : 
        manager           : 
        addressCity       :
        domainName        :
        entity            : @{entityId=1; rootEntityId=0; path=Primary Site; name=Primary Site}
        dateUpdated       : 2020-06-19T14:25:33.883Z
        recordStatus      : Retired
        identifiers       : {@{identifierID=1; identifierType=Login; value=eric.hart@logrhythm.com; recordStatus=Active; source=}, @{identifierID=2; identifierType=Email;        
                            value=eric.hart@logrhythm.com; recordStatus=Active; source=}}
        groups            : {@{name=Domain Admins}}

        identityID        : 7
        nameFirst         : Eric
        nameMiddle        :
        nameLast          : Hart
        displayIdentifier : Eric.Hart
        company           : LogRhythm Inc.
        department        : Customer Success
        title             :
        manager           :
        addressCity       :
        domainName        :
        entity            : @{entityId=1; rootEntityId=0; path=Primary Site; name=Primary Site}
        dateUpdated       : 2020-06-19T13:37:28.86Z
        recordStatus      : Active
        identifiers       : {@{identifierID=4; identifierType=Login; value=eric.hart@logrhythm.com; recordStatus=Active; source=}, @{identifierID=5; identifierType=Email;        
                            value=eric.hart@logrhythm.com; recordStatus=Active; source=}}
        groups            : {@{name=Domain Admins}}
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [int32[]] $Id,


        [Parameter(Mandatory = $false, Position = 1)]
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

        # Define HTTP Destination URI
        $RequestUrl = $BaseUrl + "/lr-admin-api/identities/query/"

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Define HTTP Body
        $Body = [PSCustomObject]@{
            ids = @($Id)
        } | ConvertTo-Json

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
        
        return $Response
    }

    End { }
}