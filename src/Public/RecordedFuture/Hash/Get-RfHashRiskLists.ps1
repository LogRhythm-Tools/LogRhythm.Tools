using namespace System
using namespace System.Collections.Generic

Function Get-RfHashRiskLists {
    <#
    .SYNOPSIS
        Retrieve the available RecordedFuture Hash threat lists.
    .DESCRIPTION
        List Hash Risk rules.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.

    .PARAMETER NamesOnly
        Returns only the Name value of the associated list.

        This object is returned as an array to support passing arrays via pipeline as a parameter.
    .PARAMETER DescriptionsOnly
        Returns only the Description value of the associated list.

        This object is returned as an array to support passing arrays via pipeline as a parameter.
    .INPUTS
        Switch -> NamesOnly
        Switch -> DescriptionsOnly
    .EXAMPLE
        Get-RfHashRiskLists
        ---
        name             : linkedToMalware
        count            : 243971076
        criticalityLabel : Suspicious
        description      : Linked to Malware
        criticality      : 2
        relatedEntities  : {}

        name             : threatResearcher
        count            : 78650
        criticalityLabel : Unusual
        description      : Threat Researcher
        criticality      : 1
        relatedEntities  : {}

        name             : rfTrending
        count            : 23
        criticalityLabel : Unusual
        description      : Trending in Recorded Future Analyst Community
        criticality      : 1
        relatedEntities  : {}

        name             : analystNote
        count            : 3823
        criticalityLabel : Unusual
        description      : Reported by Insikt Group
        criticality      : 1
        relatedEntities  : {}

        name             : linkedToVector
        count            : 4379138
        criticalityLabel : Suspicious
        description      : Linked to Attack Vector
        criticality      : 2
        relatedEntities  : {}

        name             : observedMalwareTesting
        count            : 1284
        criticalityLabel : Malicious
        description      : Observed in Underground Virus Testing Sites
        criticality      : 3
        relatedEntities  : {}

        name             : malwareSsl
        count            : 3454
        criticalityLabel : Malicious
        description      : Malware SSL Certificate Fingerprint
        criticality      : 3
        relatedEntities  : {}

        name             : historicalThreatListMembership
        count            : 29195
        criticalityLabel : Unusual
        description      : Historically Reported in Threat List
        criticality      : 1
        relatedEntities  : {}

        name             : linkedToCyberAttack
        count            : 1264430
        criticalityLabel : Suspicious
        description      : Linked to Cyber Attack
        criticality      : 2
        relatedEntities  : {}

        name             : recentActiveMalware
        count            : 7549
        criticalityLabel : Malicious
        description      : Recently Active Targeting Vulnerabilities in the Wild
        criticality      : 3
        relatedEntities  : {aHTyRv}

        name             : linkedToVuln
        count            : 1073935
        criticalityLabel : Suspicious
        description      : Linked to Vulnerability
        criticality      : 2
        relatedEntities  : {}

        name             : positiveMalwareVerdict
        count            : 317737483
        criticalityLabel : Malicious
        description      : Positive Malware Verdict
        criticality      : 3
        relatedEntities  : {}
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
        $RequestUrl = $BaseUrl + "/v2/hash/riskrules"
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