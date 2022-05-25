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
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its status.
    .EXAMPLE
        PS C:\> Add-LrIdentityIdentifier -IdentityId 8 -IdentifierType "email" -IdentifierValue "mynewid@example.com" -PassThru
        ---
        identifierID    identifierType value                    recordStatus
        ------------    -------------- -----                    ------------
        8               Email          mynewid@example.com      Active      
    .EXAMPLE
        Attempting to add an identifier to a TrueIdentity where the identifier exists

        PS C:\> Add-LrIdentityIdentifier -IdentityId 8 -IdentifierType "email" -IdentifierValue "mynewid@example.com" -PassThru
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
    .EXAMPLE
        PS C:\> Add-LrIdentityIdentifier -IdentityId 8 -IdentifierType "email" -IdentifierValue "myverynewid@example.com"
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [int] $IdentityId,


        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 1)]
        [ValidateSet('login', 'email', ignorecase=$true)]
        [string] $IdentifierType = "Login",


        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 2)]
        [string] $IdentifierValue,

                
        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 4)]
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

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            Code                  =   $null
            Type                  =   $IdentifierType
            IdentityId            =   $IdentityId
            NameFirst             =   $null
            NameLast              =   $null
            Raw                   =   $null
        }


        $ValidStatus = @("login", "email")
        if ($ValidStatus.Contains($($IdentifierType.ToLower()))) {
            $_identifierType = (Get-Culture).TextInfo.ToTitleCase($IdentifierType)
        }


        # Define HTTP Body
        $Body = @{
            value = $IdentifierValue
            identifierType = $_identifierType
         } | ConvertTo-Json

        Write-Verbose $Body
        
        # Define Endpoint URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/identities/" + $IdentityId + "/identifiers"

        # Test if Identifier exists
        $IdentifierStatus = Test-LrIdentityIdentifierValue -IdentityId $IdentityId -IdentifierType $IdentifierType -Value $IdentifierValue

        # Send Request if Identifier is Not Present
        if ($IdentifierStatus.IsPresent -eq $False) {
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
            if ($Response.Error) {
                return $Response
            }
        } else {
            $Response = $IdentifierStatus
        }
        
        if ($PassThru) {
            return $Response
        }
    }

    End { }
}