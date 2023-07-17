using namespace System
using namespace System.Collections.Generic

Function Get-RfIPRiskLists {
    <#
    .SYNOPSIS
        Retrieve the available RecordedFuture IP threat lists.
    .DESCRIPTION
        List IP Risk rules.
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
        PS C:\> Get-RfIPRiskLists
        ---
        name             : recentActiveCnc
        count            : 446
        criticalityLabel : Very Malicious
        description      : Actively Communicating C&C Server
        criticality      : 4
        relatedEntities  : {aLubo1}

        name             : spam
        count            : 121169
        criticalityLabel : Unusual
        description      : Historical Spam Source
        criticality      : 1
        relatedEntities  : {}

        name             : cyberSignalHigh
        count            : 0
        criticalityLabel : Unusual
        description      : Cyber Exploit Signal: Important
        criticality      : 1
        relatedEntities  : {}

        name             : maliciousPacketSource
        count            : 17322
        criticalityLabel : Suspicious
        description      : Malicious Packet Source
        criticality      : 2
        relatedEntities  : {}

        name             : ssl
        count            : 5825
        criticalityLabel : Unusual
        description      : Historical Bad SSL Association
        criticality      : 1
        relatedEntities  : {}

        name             : recentOpenProxies
        count            : 15591
        criticalityLabel : Suspicious
        description      : Recent Open Proxies
        criticality      : 2
        relatedEntities  : {}

        name             : threatResearcher
        count            : 76310
        criticalityLabel : Unusual
        description      : Historical Threat Researcher
        criticality      : 1
        relatedEntities  : {}

        name             : rfTrending
        count            : 314
        criticalityLabel : Unusual
        description      : Trending in Recorded Future Analyst Community
        criticality      : 1
        relatedEntities  : {}

        name             : malwareDelivery
        count            : 21
        criticalityLabel : Suspicious
        description      : Malware Delivery
        criticality      : 2
        relatedEntities  : {}

        name             : intermediateCncServer
        count            : 1122
        criticalityLabel : Suspicious
        description      : Recent C&C Server
        criticality      : 2
        relatedEntities  : {}

        name             : linkedToAPT
        count            : 3419
        criticalityLabel : Unusual
        description      : Historically Linked to APT
        criticality      : 1
        relatedEntities  : {}

        name             : recentThreatResearcher
        count            : 283
        criticalityLabel : Suspicious
        description      : Recent Threat Researcher
        criticality      : 2
        relatedEntities  : {}

        name             : bogusBgp
        count            : 18165
        criticalityLabel : Unusual
        description      : Inside Possible Bogus BGP Route
        criticality      : 1
        relatedEntities  : {}

        name             : recentlyDefaced
        count            : 1269
        criticalityLabel : Suspicious
        description      : Recently Defaced Site
        criticality      : 2
        relatedEntities  : {}

        name             : sshDictAttacker
        count            : 3315835
        criticalityLabel : Unusual
        description      : Historical SSH/Dictionary Attacker
        criticality      : 1
        relatedEntities  : {}

        name             : phishingHost
        count            : 11063
        criticalityLabel : Malicious
        description      : Phishing Host
        criticality      : 3
        relatedEntities  : {}

        name             : cyberSignalMedium
        count            : 0
        criticalityLabel : Unusual
        description      : Cyber Exploit Signal: Medium
        criticality      : 1
        relatedEntities  : {}

        name             : cncNameserver
        count            : 124
        criticalityLabel : Suspicious
        description      : Nameserver for C&C Server
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
        $RequestUrl = $BaseUrl + "/v2/ip/riskrules"
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