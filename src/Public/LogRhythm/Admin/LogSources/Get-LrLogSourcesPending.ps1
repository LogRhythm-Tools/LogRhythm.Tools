using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrLogSourcesPending {
    <#
    .SYNOPSIS
        Retrieve a list of pending Log Sources from the LogRhythm SIEM.
    .DESCRIPTION
        Get-LrLogSourcesPending returns a list of pending Log Sources, including details.
    .PARAMETER SystemMonitorId
        Filters results for a specific System Monitor Id in resources.
    .PARAMETER Name
        String used to search Entity Host records by Name.
    .PARAMETER LogSourceAcceptanceStatus
        Filters records by object LogSourceAcceptanceStatus

        Valid values: All, Pending, Rejected
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.

    .OUTPUTS
        PSCustomObject representing LogRhythm Pending Log Sources and their contents.
    .EXAMPLE
        PS C:\>  Get-LrLogSourcesPending -SystemMonitorId 4

        systemMonitorId             : 4
        name                        : 172.17.5.20
        logSourceType               :
        mpePolicy                   :
        ip                          : 172.17.5.20
        resolveKnownHost            :
        latestLogMsg                : <29>2022-05-27T10:30:45.466-0600 52a3c1931a0a ./image.binary[1]: |beatname=opencollector pulse|objectname=opencollector|status=Service is Running|vmid=2|tag1=Service is
                                    Running|original_message={"service_name":"opencollector","status":{"code":2,"description":"Service is Running"},"time":{"seconds":165366904546338020
        searchScope                 : ParentEntitySearch
        searchResult                : MultipleMsgSources
        reasonDuplicateMsgSourceIds : 201, 282
        acceptanceStatus            : Pending
        logInterfaceType            : Syslog
        collectionHost              : Entity: Primary Site, Host: TAM-DP0
        silentLogSourceDetection    : @{Enabled=False}
        resolveKnownHostEntity      :
        msgSourceAcceptanceID       : 110
        dateUpdated                 : 2022-05-27T16:31:38.79Z
        lastRequestDate             : 2022-05-27T16:31:38.79Z

        systemMonitorId          : 4
        name                     : eventhubbeat_ehbinstance1
        LogHostName              : eventhubbeat_ehbinstance1
        logSourceType            :
        mpePolicy                :
        ip                       :
        resolveKnownHost         :
        latestLogMsg             : <29>2022-05-27T10:10:35.795-0600 52a3c1931a0a ./image.binary[1]: |beatname=eventhubbeat|device_type=heartbeat|fullyqualifiedbeatname=eventhubbeat_ehbinstance1|result=2|version=|reason=Service is
                                Running|seconds=1653667835795272700|tag1=Service is Running|original_message={"@metadata":{"beat":"eventhubbeat","type":"doc","version":"6.6.0"},"@timestamp":"2022-05-27T16:10:35.795Z","beat":{"hostname":"2c392bb7e81b","name":"2c392bb7e81b","v
                                ersion":"6.6.0"},"fullyqualifiedbeatname":"eventhubbeat_ehbinstance1","heartbeat":"{\"service_name\":\"eventhubbeat\",\"service_version\":\"\",\"time\":{\"seconds\":1653667835795272789},\"status\":{\"code\":2,\"description\":\"Service is
                                Running\"}}","host":{"name":"2c392bb7e81b
        searchScope              : ParentEntitySearch
        searchResult             : NoMsgSources
        acceptanceStatus         : Pending
        logInterfaceType         : Syslog
        collectionHost           : Entity: Primary Site, Host: TAM-DP0
        silentLogSourceDetection : @{Enabled=False}
        resolveKnownHostEntity   :
        msgSourceAcceptanceID    : 123
        dateUpdated              : 2022-05-27T16:11:24.98Z
        lastRequestDate          : 2022-05-27T16:11:24.98Z

        systemMonitorId          : 4
        name                     : webhookbeat_sdp2
        LogHostName              : webhookbeat_SDP2
        logSourceType            :
        mpePolicy                :
        ip                       :
        resolveKnownHost         :
        latestLogMsg             : <29>2022-05-27T09:57:19.043-0600 52a3c1931a0a ./image.binary[1]: |beatname=webhookbeat|device_type=heartbeat|fullyqualifiedbeatname=webhookbeat_SDP2|result=2|version=|reason=Service is Running|seconds=1653667039043015400|tag1=Service is Runnin
                                g|original_message={"@metadata":{"beat":"webhookbeat","type":"doc","version":"6.6.0"},"@timestamp":"2022-05-27T15:57:19.043Z","beat":{"hostname":"a6fc87bf3d86","name":"a6fc87bf3d86","version":"6.6.0"},"fullyqualifiedbeatname":"webhookbeat_SDP2
                                ","heartbeat":"{\"service_name\":\"webhook\",\"service_version\":\"\",\"time\":{\"seconds\":1653667039043015441},\"status\":{\"code\":2,\"description\":\"Service is Running\"}}","host":{"name":"a6fc87bf3d86
        searchScope              : ParentEntitySearch
        searchResult             : NoMsgSources
        acceptanceStatus         : Pending
        logInterfaceType         : Syslog
        collectionHost           : Entity: Primary Site, Host: TAM-DP0
        silentLogSourceDetection : @{Enabled=False}
        resolveKnownHostEntity   :
        msgSourceAcceptanceID    : 119
        dateUpdated              : 2022-05-27T15:58:09.537Z
        lastRequestDate          : 2022-05-27T15:58:09.537Z
    .EXAMPLE
        Get-LrLogSourcesPending -logSourceAcceptanceStatus 'rejected' -Verbose

        systemMonitorId          : 46
        name                     : 10.128.65.193
        logSourceType            :
        mpePolicy                :
        ip                       : 10.128.65.193
        resolveKnownHost         :
        latestLogMsg             :
        searchScope              : ParentEntitySearch
        searchResult             : NoMsgSources
        acceptanceStatus         : Rejected
        logInterfaceType         : Syslog
        collectionHost           : Entity: Primary Site, Host: TAM-DC
        silentLogSourceDetection : @{Enabled=False}
        resolveKnownHostEntity   :
        msgSourceAcceptanceID    : 98
        dateUpdated              : 2022-05-27T16:42:03.233Z
        lastRequestDate          : 2022-05-25T02:55:41.42Z
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Name,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [int32] $SystemMonitorId,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidateSet('all','pending','rejected', ignorecase=$true)]
        [string] $logSourceAcceptanceStatus = "pending",


        [Parameter(Mandatory = $false, Position = 3)]
        [int] $PageValuesCount = 1000,

        
        [Parameter(Mandatory = $false, Position = 4)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch] $Exact,

        
        [Parameter(Mandatory = $false, Position = 6)]
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
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy        
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7\.[0-4]\.\d+') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.5.0 and greater."
            return $ErrorObject
        }

        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # PageCount
        if ($PageValuesCount) {
            $_pageValueCount = $PageValuesCount
        } else {
            $_pageValueCount = 1000
        }
        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $_pageValueCount)

        # Query Offset - PageCount
        $Offset = ($PageCount -1) * $_pageValueCount
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if ($Name) {
            $_name = $Name
            $QueryParams.Add("name", $_name)
        }


        # Filter by Message Source Type Id Name
        if ($MessageSourceTypeId) {
            $_messageSourceTypeId = $MessageSourceTypeId
            $QueryParams.Add("messageSourceTypeId", $_messageSourceTypeId)
        }

        # Filter by System MonitorId
        if ($SystemMonitorId) {
            $_systemMonitorId = $SystemMonitorId
            $QueryParams.Add("systemMonitorId", $_systemMonitorId)
        }

        # Return results direction, ascending or descending
        if ($Direction) {
            $ValidStatus = "ASC", "DESC"
            if ($ValidStatus.Contains($($Direction.ToUpper()))) {
                if($Direction.ToUpper() -eq "ASC") {
                    $_direction = "ascending"
                } else {
                    $_direction = "descending"
                }
                $QueryParams.Add("dir", $_direction)
            } else {
                throw [ArgumentException] "Direction [$Direction] must be: asc or desc."
            }
        }



        # RecordStatus
        if ($logSourceAcceptanceStatus) {
            $_recordStatus = [CultureInfo]::InvariantCulture.TextInfo.ToTitleCase($logSourceAcceptanceStatus.ToLowerInvariant())
            $QueryParams.Add("logSourceAcceptanceStatus", $_recordStatus)
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/logsources-request/" + $QueryString

        Write-Verbose "URL: $RequestUrl"
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Check if pagination is required, if so - paginate!
        if ($Response.Count -eq $PageValuesCount) {
            DO {
                # Increment Page Count / Offset
                $PageCount = $PageCount + 1
                $Offset = ($PageCount -1) * $PageValuesCount
                # Update Query Paramater
                $QueryParams.offset = $Offset
                # Apply to Query String
                $QueryString = $QueryParams | ConvertTo-QueryString
                # Update Query URL
                $RequestUrl = $BaseUrl + "/lr-admin-api/logsources/" + $QueryString
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if ($PaginationResults.Error) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $PageValuesCount)
        }

        # [Exact] Parameter
        # Search "Malware" normally returns both "Malware" and "Malware Options"
        # This would only return "Malware"
        if ($Exact) {
            $Pattern = "^$Name$"
            $Response | ForEach-Object {
                if(($_.name -match $Pattern) -or ($_.name -eq $Name)) {
                    Write-Verbose "[$Me]: Exact list name match found."
                    $List = $_
                    return $List
                }
            }
        } else {
            return $Response
        }
    }

    End {
    }
}