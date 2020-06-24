using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Disable-LrIdentityIdentifier {
    <#
    .SYNOPSIS
        Retire an Identifier from an existing TrueIdentity based on TrueID # and Identifier #.
    .DESCRIPTION
        Retire-LrIdentityIdentifier returns an object containing the detailed results of the retired Identifier.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER IdentityId
        Unique Identifier ID # for a TrueID record.
    .PARAMETER IdentifierId
        Unique Identifier ID # for an Identifier record.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its retirement status.
    .EXAMPLE
        Identity and Identifier exists and IdentifierStatus Active prior to cmdlet execution:
        PS C:\> Retire-LrIdentityIdentifier -IdentityId 1 -IdentifierId 50

        identifierID identifierType value                      recordStatus
        ------------ -------------- -----                      ------------
        50           Email          marcus.burnett@contaso.com Retired
    .EXAMPLE
        Identity and Identifier exists and IdentityStatus Retired prior to cmdlet execution:

        PS C:\> Retire-LrIdentityIdentifier -IdentityId 1 -IdentifierId 50

        IsPresent           : True
        IdentifierId        : 50
        Value               : marcus.burnett@contaso.com
        IdentifierType      : Email
        RecordStatus        : Retired
        IdentityId          : 1
        IdentityValid       : True
        IdentityStatus      : Active
        IdentityDisplayName : marcus.burnett@fabrikam.com

    .EXAMPLE
        Identity does not exist:
        
        PS C:\> Retire-LrIdentityIdentifier -IdentityId 77 -IdentifierId 50

        IsPresent           : False
        IdentifierId        : 50
        Value               :
        IdentifierType      :
        RecordStatus        :
        IdentityId          : 77
        IdentityValid       : False
        IdentityStatus      :
        IdentityDisplayName :

    .EXAMPLE
        Identifier does not exist:

        Retire-LrIdentityIdentifier -IdentityId 1 -IdentifierId 77

        IsPresent           : False
        IdentifierId        : 77
        Value               :
        IdentifierType      :
        RecordStatus        :
        IdentityId          : 1
        IdentityValid       : True
        IdentityStatus      : Active
        IdentityDisplayName : marcus.burnett@fabrikam.com
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
        [long]$IdentityId,

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 2)]
        [long]$IdentifierId
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        
        # Define HTTP Method
        $Method = $HttpMethod.Put

        # Establish Body Contents
        $BodyContents = [PSCustomObject]@{
            recordStatus = "Retired"
        } | ConvertTo-Json

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {        
        # Define Query URL
        $RequestUrl = $BaseUrl + "/identities/" + $IdentityId + "/identifiers/" + $IdentifierId + "/status/"


        # Test if Identifier exists
        $IdentifierStatus = Test-LrIdentityIdentifierId -IdentityId $IdentityId -Id $IdentifierId

        # Send Request and proceed if Identifier is Present
        if ($IdentifierStatus.IsPresent -eq $True -and $IdentifierStatus.RecordStatus -eq "Active") {
            # Send Request
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
                }
                catch {
                    $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose "Exception Message: $ExceptionMessage"
                    return $false
                }
            } else {
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
                }
                catch [System.Net.WebException] {
                    $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                    Write-Verbose "Exception Message: $ExceptionMessage"
                    return $false
                }
            }
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                Write-Host "Exception invoking Rest Method: [$($Err.statusCode)]: $($Err.message)" -ForegroundColor Yellow
                $PSCmdlet.ThrowTerminatingError($PSItem)
                return $false
            }
        } else {
            $Response = $IdentifierStatus
        }

        return $Response
    }

    End { }
}