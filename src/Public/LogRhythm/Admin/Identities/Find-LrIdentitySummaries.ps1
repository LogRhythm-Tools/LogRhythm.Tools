using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Find-LrIdentitySummaries {
    <#
    .SYNOPSIS
        Retrieve a list of Identities from TrueIdentity based on matching Login or TrueIdentity ID.
    .DESCRIPTION
        Find-LrIdentitySummaries returns a full LogRhythm List object, including it's details and list items.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Login
        String value that represents a TrueIdentity Identifier with type Login.

        Supports an array of Logins.
    .PARAMETER Id
        Int32 value that represents a TrueIdentity ID record.

        Supports an array of TrueIdentity ID values.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identities and their contents.
    .EXAMPLE
        C:\> Find-LrIdentitySummaries -Login eric.hart@logrhythm.com
        ---
        id          : 7
        nameFirst   : Eric
        nameMiddle  :
        nameLast    : Hart
        login1      : Eric.Hart
        title       :
        addressCity : 
        department  : Customer Success
        company     : LogRhythm Inc.
        manager     :
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [string[]] $Login,


        [Parameter(Mandatory = $false, Position = 1)]
        [int32[]] $Id,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Define HTTP Destination URI
        $RequestUrl = $BaseUrl + "/identities/summaries/query/"

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
            Raw                   =   $null
        }

        # Define HTTP Body
        $BodyContents = [PSCustomObject]@{
            logins = @($Login)
            ids = @($Id)
        }

        $Body = $BodyContents | ConvertTo-Json
        Write-Verbose "[$Me] Request Body:`n$Body"

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }
        
        return $Response
    }

    End { }
}