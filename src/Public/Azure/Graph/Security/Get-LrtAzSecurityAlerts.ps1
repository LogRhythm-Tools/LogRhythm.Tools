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

        #region: Process Query Parameters
        $QueryParams = [Dictionary[string,string]]::new()
        $QueryODataAnd = [List[string]]::new()
        $QueryODataOr = [List[string]]::new()


        if ($AzureATP) {
            if ($Filter -eq $true) {
                $QueryODataOr.Add("vendorInformation/provider eq `'Azure Advanced Threat Protection`'")
            } else {
                $QueryParams.Add("`$filter", "vendorInformation/provider eq `'Azure Advanced Threat Protection`'")
                $Filter = $true
            }
        }
        
        if ($AzureSecurityCenter) {
            if ($Filter -eq $true) {
                $QueryODataOr.Add("vendorInformation/provider eq `'ASC`'")
            } else {
                $QueryParams.Add("`$filter", "vendorInformation/provider eq `'ASC`'")
                $Filter = $true
            }
        }
        

        if ($MCAS) {
            if ($Filter -eq $true) {
                $QueryODataOr.Add("vendorInformation/provider eq `'MCAS`'")
            } else {
                $QueryParams.Add("`$filter", "vendorInformation/provider eq `'MCAS`'")
                $Filter = $true
            }
        }

        if ($AzureADIdentityProtection) {
            if ($Filter -eq $true) {
                $QueryODataOr.Add("vendorInformation/provider eq `'IPC`'")
            } else {
                $QueryParams.Add("`$filter", "vendorInformation/provider eq `'IPC`'")
                $Filter = $true
            }
        }

        
        if ($AzureSentinel) {
            if ($Filter -eq $true) {
                $QueryODataOr.Add("vendorInformation/provider eq `'Azure Sentinel`'")
            } else {
                $QueryParams.Add("`$filter", "vendorInformation/provider eq `'Azure Sentinel`'")
                $Filter = $true
            }
        }

        if ($DefenderATP) {
            if ($Filter -eq $true) {
                $QueryODataOr.Add("vendorInformation/provider eq `'Microsoft Defender ATP`'")
            } else {
                $QueryParams.Add("`$filter", "vendorInformation/provider eq `'Microsoft Defender ATP`'")
                $Filter = $true
            }
        }

        if ($Status) {
            if ($Filter -eq $true) {
                $QueryODataAnd.Add("Status eq `'$Status`'")
            } else {
                $QueryParams.Add("`$filter","Status eq `'$Status`'")
                $Filter = $true
            }
        }

        if ($Severity) {
            if ($Filter -eq $true) {
                $QueryODataAnd.Add("Severity eq `'$Severity`'")
            } else {
                $QueryParams.Add("`$filter","Severity eq `'$Severity`'")
                $Filter = $true
            }
        }


        if ($Category) {
            if ($Filter -eq $true) {
                $QueryODataAnd.Add("Category eq `'$Category`'")
            } else {
                $QueryParams.Add("`$filter","Category eq `'$Category`'")
                $Filter = $true
            }
        }



        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        if ($QueryODataOr.Count -gt 0) {
            ForEach ($ODataOr in $QueryODataOr) {
                $QueryFilterOr += $QueryFilterOr + " or " + $ODataOr
            }
            $QueryString += $QueryFilterOr
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        if ($QueryODataAnd.Count -gt 0) {
            ForEach ($ODataAnd in $QueryODataAnd) {
                $QueryFilterAnd += $QueryFilterAnd + " and " + $ODataAnd
            }
            $QueryString += $QueryFilterAnd
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        if ($Top) {
            $QueryString = $QueryString + "&`$top=$Top"
        }

        $RequestUrl = $RequestUri + $QueryString


        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUrl `
                -Headers $Headers `
                -Method $Method `
        } catch {
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
            $PageCount = 0
            # Begin paging until no more pages.
            while ($Paging) {
                Write-Verbose ">>>> More Results, calling next page <<<<"
                $PageCount += 1

                # Make the next request, using the nextLink property.
                try {
                    $Response = Invoke-RestMethod `
                        -Uri $NextPage `
                        -Headers $Headers `
                        -Method $Method `
                } catch {
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
                } elseif ($PageCount -ge 20) {
                    $Paging = $false
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