using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrtAzUserManager {
    <#
    .SYNOPSIS
        Retrieve a list of user signIn for an Azure Active Directory tenant.
    .DESCRIPTION
        The Get-SrfAzRiskySignIns cmdlet retrieves a list of signIn objects. The list 
        contains the user sign-ins for your Azure Active Directory tenant. Sign-ins where
        a username and password are passed as part of an authorization token, and successful
        federated sign-ins are currently included in the sign-in logs. 
        
        The most recent sign-ins are returned first.
    .PARAMETER Token
        An access token issued by the Microsoft identity platform with a valid claim to Microsoft
        Graph. The registered application will require the IdentityRiskyUser.Read.All role.
    .PARAMETER Top
        The Top parameter sets the page size of results.
    .INPUTS
        None
    .OUTPUTS
        A collection of signIn objects designed as being "At Risk" by the Identity platform.
        https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta#properties
    .EXAMPLE
        PS C:\> 
    .NOTES
        Azure-API
    .LINK
        https://github.com/GeneCupstid/SRF-Private
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $true, Position = 0)]
        [string] $userPrincipalName
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $AccessToken = Get-LrtAzToken -ResourceName AzureAd | Select-Object -ExpandProperty access_token
        
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $AccessToken")


        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }


    Process {
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Request URI
        # https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=http
        $Method = $HttpMethod.Get
        $RequestUri = "https://graph.microsoft.com/v1.0/users/$userPrincipalName/manager"


        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method
        } catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        
        #endregion

        return $Response
    }

    End { }
}