using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrtAzSecurityAlerts {
    <#
    .SYNOPSIS
        Retrieve a list of user signIn for an Azure Active Directory tenant.
    .DESCRIPTION
        The Get-SrfAzRiskySignIns cmdlet retrieves a list of signIn objects. The list 
        contains the user sign-ins for your Azure Active Directory tenant. Sign-ins where
        a username and password are passed as part of an authorization token, and successful
        federated sign-ins are currently included in the sign-in logs. 
        
        The most recent sign-ins are returned first.
    .PARAMETER CreatedDateTime
        Time at which the alert was created by the alert provider. The Timestamp type represents
        date and time information using ISO 8601 format and is always in UTC time. For example, 
        midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. 
        
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
        [ValidateSet('high','medium', 'low', 'informational', ignorecase=$true)]
        [string] $Severity,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)]
        #[ValidateSet('UnfamiliarLocation','Ransomware', '', '', ignorecase=$true)]
        [string] $Category,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 2)]
        [ValidateSet('unknown','newAlert', 'inProgress', 'resolved', ignorecase=$true)]
        [string] $Status,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 4)]
        [int32] $Top,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch] $AzureATP,


        [Parameter(Mandatory = $false, Position = 6)]
        [switch] $AzureSecurityCenter,


        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $MCAS,


        [Parameter(Mandatory = $false, Position = 8)]
        [switch] $AzureADIdentityProtection,


        [Parameter(Mandatory = $false, Position = 9)]
        [switch] $AzureSentinel,


        [Parameter(Mandatory = $false, Position = 10)]
        [switch] $DefenderATP
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $AccessToken = Get-LrtAzToken -ResourceName AzureAd | Select-Object -ExpandProperty access_token
        

        $Filter = $false

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
        $RequestUri = "https://graph.microsoft.com/v1.0/security/alerts"



        if ($Severity) {
            if ($Filter -eq $true) {
                $RequestUri += "&Severity eq `'$Severity`'"
            } else {
                $RequestUri += "?`$filter=Severity eq `'$Severity`'"
                $Filter = $true
            }
        }


        if ($Category) {
            if ($Filter -eq $true) {
                $RequestUri += "&Category eq `'$Category`'"
            } else {
                $RequestUri += "?`$filter=Category eq `'$Category`'"
                $Filter = $true
            }
        }


        if ($Status) {
            if ($Filter -eq $true) {
                $RequestUri += "&Status eq `'$Status`'"
            } else {
                $RequestUri += "?`$filter=Status eq `'$Status`'"
                $Filter = $true
            }
        }


        if ($AzureATP) {
            if ($Filter -eq $true) {
                $RequestUri += "&vendorInformation/provider eq `'Azure Advanced Threat Protection`'"
            } else {
                $RequestUri += "?`$filter=vendorInformation/provider eq `'Azure Advanced Threat Protection`'"
                $Filter = $true
            }
        }


        if ($AzureSecurityCenter) {
            if ($Filter -eq $true) {
                $RequestUri += "&vendorInformation/provider eq `'ASC`'"
            } else {
                $RequestUri += "?`$filter=vendorInformation/provider eq `'ASC`'"
                $Filter = $true
            }
        }


        if ($MCAS) {
            if ($Filter -eq $true) {
                $RequestUri += "&vendorInformation/provider eq `'MCAS`'"
            } else {
                $RequestUri += "?`$filter=vendorInformation/provider eq `'MCAS`'"
                $Filter = $true
            }
        }


        if ($AzureADIdentityProtection) {
            if ($Filter -eq $true) {
                $RequestUri += "&vendorInformation/provider eq `'IPC`'"
            } else {
                $RequestUri += "?`$filter=vendorInformation/provider eq `'IPC`'"
                $Filter = $true
            }
        }


        if ($AzureSentinel) {
            if ($Filter -eq $true) {
                $RequestUri += "&vendorInformation/provider eq `'Azure Sentinel`'"
            } else {
                $RequestUri += "?`$filter=vendorInformation/provider eq `'Azure Sentinel`'"
                $Filter = $true
            }
        } 


        if ($DefenderATP) {
            if ($Filter -eq $true) {
                $RequestUri += "&vendorInformation/provider eq `'Microsoft Defender ATP`'"
            } else {
                $RequestUri += "?`$filter=vendorInformation/provider eq `'Microsoft Defender ATP`'"
                $Filter = $true
            }
        }


        if ($Top) {
            $RequestUri += "&`$top=$Top"
        }


        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method `
        } catch [System.Net.WebException] {
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
                } catch [System.Net.WebException] {
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
        #>
        
        #endregion

        return $ResultSet
    }

    End { }
}