using namespace System
using namespace System.Collections.Generic

Function Get-RfDomainRiskLists {
    <#
    .SYNOPSIS
        Retrieve the available RecordedFuture Domain threat lists.
    .DESCRIPTION
        
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.

    .PARAMETER NamesOnly
        Returns only the Name value of the associated list.

        This object is returned as an array to support passing arrays via pipeline as a parameter.
    .PARAMETER DescriptionsOnly
        Returns only the Description value of the associated list.

        This object is returned as an array to support passing arrays via pipeline as a parameter.
    .EXAMPLE
        PS C:\> Get-RfDomainRiskLists           
        ---
        name             : recentTyposquatTypo
        count            : 199393
        criticalityLabel : Unusual
        description      : Recent Typosquat Similarity - Typo or Homograph
        criticality      : 1
        relatedEntities  : {}

        name             : recentSuspiciousContent
        count            : 0
        criticalityLabel : Suspicious
        description      : URL Recently Linked to Suspicious Content
        criticality      : 2
        relatedEntities  : {}

        name             : relatedNote
        count            : 901
        criticalityLabel : Unusual
        description      : Historically Referenced by Insikt Group
        criticality      : 1
        relatedEntities  : {}

        name             : cncUrl
        count            : 11
        criticalityLabel : Suspicious
        description      : C&C URL
        criticality      : 2
        relatedEntities  : {}

        name             : resolvedVeryMaliciousIp
        count            : 222
        criticalityLabel : Suspicious
        description      : Recently Resolved to Very Malicious IP
        criticality      : 2
        relatedEntities  : {}

        name             : fastFlux
        count            : 7946
        criticalityLabel : Suspicious
        description      : Recent Fast Flux DNS Name
        criticality      : 2
        relatedEntities  : {}
    .NOTES
        RecordedFuture-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [switch] $NamesOnly,

        [Parameter(Mandatory = $false, Position = 1)]
        [switch] $DescriptionsOnly,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.RecordedFuture.ApiKey
    )

    Begin {
        $BaseUrl = $LrtConfig.RecordedFuture.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("X-RFToken", $Token)

        Write-Verbose "$($Headers | Out-String)"

        # Request Setup
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish Query Parameters object
        $QueryParams = [Dictionary[string,string]]::new()

        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }



        # Define Search URL
        $RequestUrl = $BaseUrl + "/v2/domain/riskrules"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers
        }
        catch {
            If ($_.Exception.Response.StatusCode.value__) {
                $HTTPCode = ($_.Exception.Response.StatusCode.value__ ).ToString().Trim()
                Write-Verbose "HTTP Code: $HTTPCode"
            }
            If  ($_.Exception.Message) {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $ExceptionMessage
            }
        }

        # Return Values only as an array or all results as object
        if ($NamesOnly) {
            Return ,$Results.data.results.name
        } elseif ($DescriptionsOnly) {
            Return ,$Results.data.results.description
        } else {
            Return $Results.data.results
        }
    }
 

    End { }


}