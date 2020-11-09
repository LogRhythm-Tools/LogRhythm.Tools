using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function List-LrtAzMailAttachments {
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
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [string] $UserPrincipalName,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [string] $MessageId
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $AccessToken = Get-LrtAzToken -ResourceName AzureAd | Select-Object -ExpandProperty access_token
        

        $Search = $false

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }


    Process {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $AccessToken")


        # Request URI
        # https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=http
        $Method = $HttpMethod.Get
        $RequestUri = "https://graph.microsoft.com/v1.0/users/$UserPrincipalName/messages/$MessageId/attachments"


        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method `
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.error.code)]: $($Err.error.message)`n"
        }

    
        # Cast result to List<Object>
        Write-Verbose "Results: $($Response.value.count)"
        [List[Object]] $ResultSet = $Response.value


        #region: Paging                                                                  
        # Check to see if we need to keep paging.
        if ($Response.'@odata.nextLink') {
            $Paging = $true
            $NextPage = $Response.'@odata.nextLink'

            # Begin paging until no more pages.
            while ($Paging) {
                Write-Verbose ">>>> More Results, calling next page <<<<"

                # Make the next request, using the nextLink property.
                try {
                    $Response = Invoke-RestMethod `
                        -Uri $NextPage `
                        -Headers $Headers `
                        -Method $Method `
                }
                catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    throw [Exception] "[$Me] [$($Err.error.code)]: $($Err.error.message)`n"
                }

                # Cast result to List<Object> and append to ResultSet
                Write-Verbose "Results: $($Response.value.count)"
                [List[Object]] $PageSet = $Response.value
                $ResultSet.AddRange($PageSet)


                # Check if done
                if ($Response.'@odata.nextLink') {
                    $NextPage = $Response.'@odata.nextLink'
                } else {
                    $Paging = $false
                }
            }
        }
        
        #endregion

        return $ResultSet
    }

    End { }
}