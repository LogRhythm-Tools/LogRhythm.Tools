using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Disable-LrIdentity {
    <#
    .SYNOPSIS
        Retire an Identity from TrueIdentity based on TrueID #.
    .DESCRIPTION
        Disable-LrIdentity returns an object containing the detailed results of the retired Identity.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER IdentityId
        Unique Identifier ID # for a TrueID record.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its retirement status.
    .EXAMPLE
        PS C:\> Disable-LrIdentity -IdentityId 11 -PassThru
        ---
        identityID        : 11
        nameFirst         : Marcus
        nameMiddle        :
        nameLast          : Burnett
        displayIdentifier : marcus.burnett@contoso.com
        company           : Contoso
        department        : IT
        title             : IT Helpdesk Admin
        manager           : Jade Falkesan
        addressCity       :
        domainName        :
        entity            : @{entityId=1; rootEntityId=0; path=Primary Site; name=Primary Site}
        dateUpdated       : 2020-04-15T18:30:08.86Z
        recordStatus      : Retired
        identifiers       : {@{identifierID=40; identifierType=Login; value=marcus.burnett; recordStatus=Active; source=}, @{identifierID=41; identifierType=Login; value=marcus.burnett@contoso.com;
                            recordStatus=Active; source=}, @{identifierID=42; identifierType=Login; value=marcus.burnett_sup; recordStatus=Active; source=}, @{identifierID=43; identifierType=Email;
                            value=marcus.burnett@contoso.com; recordStatus=Active; source=}}
        groups            : {@{name=Domain Admins}}
    .EXAMPLE
        PS C:\> Disable-LrIdentity -IdentityId 12

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [long] $IdentityId,

                        
        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 2)]
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
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Put

        # Define Body Contents
        $Body = [PSCustomObject]@{
            recordStatus = "Retired"
        } | ConvertTo-Json

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {     
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            Code                  =   $null
            Type                  =   $null
            NameFirst             =   $NameFirst
            NameLast              =   $NameLast
            Raw                   =   $null
        }

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/identities/" + $IdentityId + "/status"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        if ($PassThru) {
            return $Response
        }
    }

    End { }
}