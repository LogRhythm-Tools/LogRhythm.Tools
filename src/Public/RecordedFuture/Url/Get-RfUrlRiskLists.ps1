using namespace System
using namespace System.Collections.Generic

Function Get-RfUrlRiskLists {
    <#
    .SYNOPSIS
        Show the available RecordedFuture Url threat lists.
    .DESCRIPTION
        
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
        PS C:\> Get-RfUrlRiskLists
        ---
        name             : maliciousSiteDetected
        count            : 56880363
        criticalityLabel : Unusual
        description      : Historically Detected Malicious Browser Exploits
        criticality      : 1
        relatedEntities  : {}

        name             : relatedNote
        count            : 2870
        criticalityLabel : Unusual
        description      : Historically Referenced by Insikt Group
        criticality      : 1
        relatedEntities  : {}

        name             : defangedURL
        count            : 423823
        criticalityLabel : Unusual
        description      : Historically Reported as a Defanged URL
        criticality      : 1
        relatedEntities  : {}

        name             : recentSpamSiteDetected
        count            : 3416
        criticalityLabel : Suspicious
        description      : Recently Reported Spam or Unwanted Content
        criticality      : 2
        relatedEntities  : {}

        name             : recentMaliciousSiteDetected
        count            : 1864821
        criticalityLabel : Malicious
        description      : Recently Detected Malicious Browser Exploits
        criticality      : 3
        relatedEntities  : {}

        name             : ransomwareDistribution
        count            : 9
        criticalityLabel : Very Malicious
        description      : Ransomware Distribution URL
        criticality      : 4
        relatedEntities  : {}

        name             : recentDhsAis
        count            : 31
        criticalityLabel : Malicious
        description      : Recently Reported by DHS AIS
        criticality      : 3
        relatedEntities  : {}

        name             : suspiciousSiteDetected
        count            : 691710
        criticalityLabel : Unusual
        description      : Historically Detected Suspicious Content
        criticality      : 1
        relatedEntities  : {}

        name             : miningSiteDetected
        count            : 366
        criticalityLabel : Unusual
        description      : Historically Detected Cryptocurrency Mining Techniques
        criticality      : 1
        relatedEntities  : {}

        name             : fraudulentContent
        count            : 0
        criticalityLabel : Unusual
        description      : Historically Reported Fraudulent Content
        criticality      : 1
        relatedEntities  : {}

        name             : cncUrl
        count            : 91
        criticalityLabel : Very Malicious
        description      : C&C URL
        criticality      : 4
        relatedEntities  : {}

        name             : recentSuspiciousSiteDetected
        count            : 21475
        criticalityLabel : Suspicious
        description      : Recently Detected Suspicious Content
        criticality      : 2
        relatedEntities  : {}

        name             : spamSiteDetected
        count            : 49595
        criticalityLabel : Unusual
        description      : Historically Reported Spam or Unwanted Content
        criticality      : 1
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
        $RequestUrl = $BaseUrl + "/v2/url/riskrules"
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