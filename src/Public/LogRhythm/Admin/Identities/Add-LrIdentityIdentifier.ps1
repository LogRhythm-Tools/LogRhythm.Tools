using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrIdentityIdentifier {
    <#
    .SYNOPSIS
        Add an Identifier to an existing TrueIdentity.
    .DESCRIPTION
        Add-LrIdentityIdentifier returns an object containing the detailed results of the added Identity.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER IdentityId
        Identity ID # for associating new TrueIdentity Identity record.
    .PARAMETER IdentifierType
        Valid options: Email, Login
    .PARAMETER IdentifierValue
        Value for the new Identifier
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its status.
    .EXAMPLE
        PS C:\> Add-LrIdentityIdentifier -IdentityId 8 -IdentifierType "email" -IdentifierValue "mynewid@example.com"
        ----
        identifierID    identifierType value                    recordStatus
        ------------    -------------- -----                    ------------
        8               Email          mynewid@example.com      Active      
    .EXAMPLE
        Attempting to add an identifier to a TrueIdentity where the identifier exists

        PS C:\> Add-LrIdentityIdentifier -IdentityId 8 -IdentifierType "email" -IdentifierValue "mynewid@example.com"
        ---
        IsPresent           : True
        IdentifierId        : 8
        Value               : mynewid@example.com
        IdentifierType      : Email
        IdentifierValid     : True
        IdentityId          : 8
        IdentityValid       : True
        IdentityStatus      : Active
        IdentityDisplayName : Eric.Hart
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

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 1)]
        [int]$IdentityId,

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 2)]
        [ValidateSet('login', 'email', ignorecase=$true)]
        [String]$IdentifierType = "Login",

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 3)]
        [String]$IdentifierValue
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

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        $ValidStatus = @("login", "email")
        if ($ValidStatus.Contains($($IdentifierType.ToLower()))) {
            $_identifierType = (Get-Culture).TextInfo.ToTitleCase($IdentifierType)
        }


        # Define HTTP Body
        $BodyContents = @{
            value = $IdentifierValue
            identifierType = $_identifierType
         } | ConvertTo-Json
        
        # Define Endpoint URL
        $RequestUrl = $BaseUrl + "/identities/" + $IdentityId + "/identifiers"

        # Test if Identifier exists
        $IdentifierStatus = Test-LrIdentityIdentifierValue -IdentityId $IdentityId -IdentifierType $IdentifierType -Value $IdentifierValue

        # Send Request if Identifier is Not Present
        if ($IdentifierStatus.IsPresent -eq $False) {
            # Send Request
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
                }
                catch {
                    $Err = Get-RestErrorMessage $_
                    Write-Verbose "Exception Message: $Err"
                    return $Err
                }
            } else {
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
                }
                catch {
                    $Err = Get-RestErrorMessage $_
                    Write-Verbose "Exception Message: $Err"
                    return $Err
                }
            }
        } else {
            $Response = $IdentifierStatus
        }
        
        return $Response
    }

    End { }
}