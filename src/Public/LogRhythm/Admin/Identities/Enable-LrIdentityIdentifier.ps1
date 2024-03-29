using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Enable-LrIdentityIdentifier {
    <#
    .SYNOPSIS
        Enable an Identifier from an existing TrueIdentity based on TrueID # and Identifier #.
    .DESCRIPTION
        Enable-LrIdentityIdentifier returns an object containing the detailed results of the enabled Identifier.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER IdentityId
        Unique Identifier ID # for a TrueID record.
    .PARAMETER IdentifierId
        Unique Identifier ID # for an Identifier record.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its status.
    .EXAMPLE
        Identity exists and Identitystatus Retired prior to cmdlet execution:

        PS C:\> Enable-LrIdentityIdentifier -IdentityId 11 -IdentifierId 50 -PassThru
        ---
        identifierID identifierType value                      recordStatus
        ------------ -------------- -----                      ------------
        50           Email          marcus.burnett@contaso.com Active

    .EXAMPLE
        Identity exists and IdentityStatus Active prior to cmdlet execution:

        PS C:\> Enable-LrIdentityIdentifier -IdentityId 11 -IdentifierId 50 -PassThru
        ---
        IsPresent           : True
        IdentifierId        : 50
        Value               : marcus.burnett@contaso.com
        IdentifierType      : Email
        RecordStatus        : Active
        IdentityId          : 1
        IdentityValid       : True
        IdentityStatus      : Active
        IdentityDisplayName : marcus.burnett@fabrikam.com
    .EXAMPLE
        Identity does not exist:

        PS C:\> Enable-LrIdentityIdentifier -IdentityId 77 -IdentifierId 50 -PassThru
        ---
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
        IdentifierId does not exist:

        PS C:\> Enable-LrIdentityIdentifier -IdentityId 1 -IdentifierId 55 -PassThru
        ---
        IsPresent           : False
        IdentifierId        : 55
        Value               :
        IdentifierType      :
        RecordStatus        :
        IdentityId          : 1
        IdentityValid       : True
        IdentityStatus      : Active
        IdentityDisplayName : marcus.burnett@fabrikam.com
    .EXAMPLE
        PS C:\> Enable-LrIdentityIdentifier -IdentityId 1 -IdentifierId 55

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [long] $IdentityId,


        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 1)]
        [long] $IdentifierId,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 3)]
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
        $Method = $HttpMethod.Put

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish Body Contents
        $Body = [PSCustomObject]@{
            recordStatus = "Active"
        } | ConvertTo-Json
        
        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/identities/" + $IdentityId + "/identifiers/" + $IdentifierId + "/status/"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Test if Identifier exists
        $IdentifierStatus = Test-LrIdentityIdentifierId -IdentityId $IdentityId -Id $IdentifierId

        # Send Request and proceed if Identifier is Present
        if ($IdentifierStatus.IsPresent -eq $True -and $IdentifierStatus.RecordStatus -eq "Retired") {
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
            if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
                return $Response
            }
        } else {
            return $IdentifierStatus
        }

        if ($PassThru) {
            return $Response
        }
    }

    End { }
}