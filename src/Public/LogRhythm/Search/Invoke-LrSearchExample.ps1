using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Invoke-LrSearchExample {
    <#
    .SYNOPSIS
        Initiate a PIE Msg search in the LogRhythm SIEM environment.  Requires LogRhythm 7.5.0+.
    .DESCRIPTION
        Invoke-PIEMsgSearch initiates a new search request.

        To retrieve search results reference cmdlet: Get-LrSearchResults.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        None
    .OUTPUTS
        PSCustomObject representing the new search task, its status, and the associated TaskId used to retrieve results.
    .EXAMPLE
        PS C:\> New-LrSearch
        ----
        StatusCode      : 200
        StatusMessage   : Success
        ResponseMessage : Success
        TaskStatus      : Searching
        TaskId          : efaa62ab-84ed-4d9e-96a9-c280973c3307
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [string] $Hostname1 = "hostname1",


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [string] $Hostname2 = "hostname2",

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [string] $IPv4Address1 = "127.0.0.2",


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [string] $IPv4Address2 = "127.0.0.3",

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNull()]
        [datetime] $BeginDate,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [datetime] $EndDate,

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
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Value Testing Paramater
        $_int = 0
    }

    Process {
        $JSON = '{"name":"Rest - SearchAPI Example","description":"This is a JSON body example to serve as a reference to perform searches for Hostname (Origin/Impacted) OR IP Address (Origin/Impacted) over a given time frame with a maximum of 30,000 logs returned.","maxMsgsToQuery":30000,"logCacheSize":10000,"aggregateLogCacheSize":10000,"queryTimeout":900,"isOriginatedFromWeb":false,"webLayoutId":0,"queryRawLog":true,"queryFilter":{"msgFilterType":2,"isSavedFilter":false,"filterGroup":{"filterItemType":1,"fieldOperator":2,"filterMode":1,"filterGroupOperator":1,"filterItems":[{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":23,"values":[{"filterType":23,"valueType":4,"value":{"value":"hostvalue1","matchType":0},"displayValue":"hostvalue1"},{"filterType":23,"valueType":4,"value":{"value":"hostvalue2","matchType":0},"displayValue":"hostvalue2"}],"name":"HostName (Origin or Impacted)"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":17,"values":[{"filterType":17,"valueType":5,"value":"127.0.0.2","displayValue":"127.0.0.2"},{"filterType":17,"valueType":5,"value":"127.0.0.3","displayValue":"127.0.0.3"}],"name":"IP Address (Origin or Impacted)"}],"name":"Filter Group"}},"queryEventManager":false,"useDefaultLogRepositories":true,"dateCreated":"2021-03-10T11:58:58.7800347Z","dateSaved":"2021-03-10T11:58:58.7800347Z","dateUsed":"2021-03-10T11:58:58.7800347Z","includeDiagnosticEvents":true,"searchMode":2,"nextPageToken":"","pagedTimeout":300,"restrictedUserId":0,"createdVia":0,"searchType":1,"queryOrigin":0,"searchServerIPAddress":null,"dateCriteria":{"useInsertedDate":false,"dateMin":"2021-03-09T05:00:00Z","dateMax":"2021-03-11T04:59:59Z"},"repositoryPattern":"","ownerId":1,"searchId":0,"queryLogSourceLists":[],"queryLogSources":[],"logRepositoryIds":[1],"refreshRate":0,"isRealTime":false,"objectSecurity":{"objectId":0,"objectType":20,"readPermissions":2,"writePermissions":2,"entityId":1,"ownerId":1,"canEdit":true,"canDelete":false,"canDeleteObject":false,"entityName":"","ownerName":"","isSystemObject":true},"enableIntelligentIndexing":false}' | ConvertFrom-Json

        #Update search paramater values for Hostname1 and Hostname2
        # Hostname1 - Value followed by DisplayValue
        $JSON.queryFilter.filterGroup.filterItems[0].values[0].value.value = $Hostname1.ToLower()
        $JSON.queryFilter.filterGroup.filterItems[0].values[0].displayValue = $Hostname1.ToLower()
        # Hostname2 - Value followed by DisplayValue
        $JSON.queryFilter.filterGroup.filterItems[0].values[1].value.value = $Hostname2.ToLower()       
        $JSON.queryFilter.filterGroup.filterItems[0].values[1].displayValue = $Hostname2.ToLower()

       
        #Update Sender
        # IPv4Address1 - Value followed by DisplayValue
        $JSON.queryFilter.filterGroup.filterItems[1].values[0].value = $IPv4Address1
        $JSON.queryFilter.filterGroup.filterItems[1].values[0].displayValue = $IPv4Address1
        # IPv4Address2 - Value followed by DisplayValue
        $JSON.queryFilter.filterGroup.filterItems[1].values[1].value = $IPv4Address2
        $JSON.queryFilter.filterGroup.filterItems[1].values[1].displayValue = $IPv4Address2

        #Update date criteria
        if ($BeginDate -and $EndDate) {
            $SearchBeginDate = $BeginDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            $SearchEndDate = $EndDate.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        } else {
            $SearchBeginDate = (get-date).AddDays(-2).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            $SearchEndDate = (get-date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }

        $JSON.dateCriteria.dateMin = $SearchBeginDate
        $JSON.DateCriteria.dateMax = $SearchEndDate

        # Establish Body Contents
        $Body = $JSON | ConvertTo-Json -Depth 20

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-search-api/actions/search-task"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        return $Response
    }

    End { 
    }

}