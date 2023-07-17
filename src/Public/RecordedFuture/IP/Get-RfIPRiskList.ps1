using namespace System
using namespace System.Collections.Generic

Function Get-RfIPRiskList {
    <#
    .SYNOPSIS
        Get RecordedFuture IP threat list.
    .DESCRIPTION
        Get RecordedFuture IP cmdlet retrieves the associated threat list results with returned IP values and their associated data.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.VirusTotal.VtApiToken
        with a valid Api Token.
    .PARAMETER List
        Name of the RecordedFuture IP ThreatList
    .PARAMETER Format
        Output format as provided by RecordedFuture.  This script currently only proceses 'csv/splunk' format.
        
        Possible formats:
        "csv/splunk", "xml/stix/1.1.1", "xml/stix/1.2"
    .PARAMETER Compressed
        Determines if the data should be compressed from RecordedFuture prior to sending to requestor.

        This script currently only supports non-compressed results.
    .PARAMETER MinimumRisk
        Sets the minimum risk value for returned object(s).  
    .PARAMETER MaximumRisk
        Sets the maximum risk value for returned object(s).
    .PARAMETER ValuesOnly
        Returns only the Name value of the associated list.

        This object is returned as an array to support passing arrays via pipeline as a parameter.
    .PARAMETER IPv4
        Sets the return object to return only Hash values that are of the IPv4 type.
    .PARAMETER IPv6
        Sets the return object to return only Hash values that are of the IPv6 type.
    .INPUTS
        String -> Token
        String -> List
        String -> Format
        Bool   -> Compressed
        Int    -> MinimumRisk
        Int    -> MaximumRisk
        Switch -> ValuesOnly
        Switch -> IPv4
        Switch -> IPv6
    .EXAMPLE
        PS C:\> Get-RfIpRiskList -List openProxies
        ---
        Name            Risk RiskString EvidenceDetails
        ----            ---- ---------- ---------------
        36.89.182.225     99 8/51       {"EvidenceDetails": [{"Rule": "Historical Honeypot Sighting", "CriticalityLabel": "Unusual", "EvidenceString": "1 sighting on 1 source: Project Honey Pot. Most recent link (Sep 10, 2018): https://www.projecthoneypot.org/ip_36.89.183.85", "Times… 
        110.93.15.98      99 5/51       {"EvidenceDetails": [{"Rule": "Historically Linked to Intrusion Method", "CriticalityLabel": "Unusual", "EvidenceString": "1 sighting on 1 source: PasteBin. 3 related intrusion methods: Trickbot, Banking Trojan, Trojan. Most recent link (Apr 13… 
        183.81.154.113    99 4/51       {"EvidenceDetails": [{"Rule": "Historically Linked to Intrusion Method", "CriticalityLabel": "Unusual", "EvidenceString": "2 sightings on 1 source: ReversingLabs. Most recent link (Dec 30, 2019): https://a1000.reversinglabs.com/accounts/login/?… 
        186.159.1.217     99 8/51       {"EvidenceDetails": [{"Rule": "Historical Honeypot Sighting", "CriticalityLabel": "Unusual", "EvidenceString": "5 sightings on 2 sources: @HoneyFog, @HoneyPyLog. Most recent tweet: Fog44: 186.159.1.217-&gt;8080. Seen 9 times from me. Most recen… 
        173.171.132.82    99 6/51       {"EvidenceDetails": [{"Rule": "Historically Linked to Intrusion Method", "CriticalityLabel": "Unusual", "EvidenceString": "7 sightings on 3 sources: @senthilkl, VirusTotal, pscforum.info. 5 related intrusion methods: Trickbot, Banking Trojan, D… 
    .EXAMPLE
        PS C:\> Get-RfIpRiskList -List openProxies -ValuesOnly -IPv4
        ---
        36.89.182.225
        110.93.15.98
        183.81.154.113
        186.159.1.217
        173.171.132.82
    .NOTES
        RecordedFuture-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $List,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Format = "csv/splunk",


        [Parameter(Mandatory = $false, Position = 2)]
        [bool] $Compressed = $false,


        [Parameter(Mandatory = $false, Position = 3)]
        [int] $MinimumRisk,


        [Parameter(Mandatory = $false, Position = 4)]
        [int] $MaximumRisk,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch] $ValuesOnly,


        [Parameter(Mandatory = $false, Position = 6)]
        [switch] $IPv4,


        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $IPv6,


        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.RecordedFuture.ApiKey
    )

    Begin {
        $ResultsList = $null
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
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $List
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
        }

        # Establish Query Parameters object
        $QueryParams = [Dictionary[string,string]]::new()

        # Format
        $QueryParams.Add("format", $Format)

        # Compression
        $QueryParams.Add("gzip", $Compressed)

        # List
        $QueryParams.Add("list", $List)


        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }



        # Define Search URL
        $RequestUrl = $BaseUrl + "/v2/ip/risklist" + $QueryString
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        Try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers | ConvertFrom-Csv
        }
        catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            return $ErrorObject
        }

        $ResultsList = @($Results | Select-Object @{Name="Name";Expression={[string]$_.Name}},@{Name="Risk";Expression={[int32]$_.Risk}},@{Name="RiskString";Expression={[string]$_.RiskString}},@{Name="EvidenceDetails";Expression={[string]$_.EvidenceDetails}})
        # Filter retuned results based on IP Address type
        if ($IPv4) {
            $ResultsList = $ResultsList.Where({[string]$_.name -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"})
        }
        elseif ($IPv6) {
            $ResultsList = $ResultsList.Where({[string]$_.name -match "^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$"})
        }

        # Filter returned results based on Risk score
        if ($MinimumRisk -and $MaximumRisk) {
            $ResultsList = $ResultsList.Where({([int32]$_.Risk -ge $MinimumRisk) -and ([int32]$_.Risk -le $MaximumRisk)})
        } elseif ($MinimumRisk) {
            $ResultsList = $ResultsList.Where({[int32]$_.Risk -ge $MinimumRisk})
        } elseif ($MaximumRisk) {
            $ResultsList = $ResultsList.Where({[int32]$_.Risk -le $MaximumRisk})
        }

        # Return Values only as an array or all results as object
        if ($ValuesOnly) {
            Return ,$ResultsList.Name
        } else {
            Return $ResultsList
        }
    }
 

    End { }
}