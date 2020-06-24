using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrIdentityById {
    <#
    .SYNOPSIS
        Retrieve an Identity from TrueIdentity based on TrueID #.
    .DESCRIPTION
        Get-LrIdentity returns an object containing the detailed results of the returned Identity.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER IdentityId
        Unique Identifier ID # for a TrueID record.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its contents.
    .EXAMPLE
        PS C:\> Get-LrIdentityById -IdentityId 1217
        ----
        identityID        : 1217
        nameFirst         : Bobby
        nameMiddle        : K
        nameLast          : Jones
        displayIdentifier : Bobby.Jones@example.com
        company           : LogRhythm
        department        : Sales
        title             : Sales Engineer
        manager           : Susan Smith
        addressCity       :
        domainName        :
        entity            : @{entityId=1; rootEntityId=0; path=Primary Site; name=Primary Site}
        dateUpdated       : 2019-12-25T00:29:58.95Z
        recordStatus      : Active
        identifiers       : {@{identifierID=5555; identifierType=Login; value=bobby.j; recordStatus=Active; source=}, @{identifierID=5556; identifierType=Login; value=bobby.j@example.com;
                            recordStatus=Active; source=}, @{identifierID=5557; identifierType=Login; value=bobby.j@demo.example.com; recordStatus=Active; source=}, @{identifierID=5558;
                            identifierType=Email; value=bobby.j@exampele.com; recordStatus=Active; source=}...}
        groups            : {@{name=Users}}


        PS C:\> Get-LrIdentityById -IdentityId 1 -IdentifiersOnly
        ----
        identifierID   : 1
        identifierType : Login
        value          : marcus.burnett
        recordStatus   : Active
        source         : @{AccountName=Source 1; IAMName=Fabrikam}

        identifierID   : 2
        identifierType : Login
        value          : marcus.burnett@fabrikam.com
        recordStatus   : Active
        source         : @{AccountName=Source 1; IAMName=Fabrikam}

        identifierID   : 3
        identifierType : Email
        value          : marcus.burnett@fabrikam.com
        recordStatus   : Retired
        source         : @{AccountName=Source 1; IAMName=Fabrikam}   
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $true, ValueFromPipeline=$true, Position = 1)]
        [long]$IdentityId,

        [Parameter(Mandatory = $false, Position = 2)]
        [switch]$IdentifiersOnly,

        [Parameter(Mandatory = $false, Position = 3)]
        [switch]$Silent
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Define Query URL
        $RequestUrl = $BaseUrl + "/identities/" + $IdentityId

        # Send Request
        if($Silent) {
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck -ErrorAction 'silentlycontinue'
                }
                catch {
                    $_.Exception.Response.StatusCode.Value__
                }
            } else {
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -ErrorAction 'silentlycontinue'
                }
                catch [System.Net.WebException] {
                    $_.Exception.Response.StatusCode.Value__
                }
            }            
        } else {
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
                }
                catch [System.Net.WebException] {
                    $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose "Exception Message: $ExceptionMessage"
                    return $ExceptionMessage
                }
            } else {
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
                }
                catch [System.Net.WebException] {
                    $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose "Exception Message: $ExceptionMessage"
                    return $ExceptionMessage
                }
            }
        }

        # Return Identity Object or array of Identifiers
        if ($IdentifiersOnly) {
            return $Response.identifiers
        } else {
            return $Response
        }
    }

    End { }
}