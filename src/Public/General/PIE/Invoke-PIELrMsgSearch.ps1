using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Invoke-PIELrMsgSearch {
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
        [string] $EmailSender,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [string] $Subject,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [string] $SOCMailbox,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
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
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            ResponseUrl           =   $null
            Value                 =   $Name
            Raw                   =   $null
        }

        $JSON = '{"name":"PIE - MsgSearch","description":"Triggered through Search API for PIE.","maxMsgsToQuery":30000,"logCacheSize":10000,"aggregateLogCacheSize":10000,"queryTimeout":540,"isOriginatedFromWeb":false,"webLayoutId":0,"queryRawLog":true,"queryFilter":{"msgFilterType":2,"isSavedFilter":false,"filterGroup":{"filterItemType":1,"fieldOperator":1,"filterMode":1,"filterGroupOperator":0,"filterItems":[{"filterItemType":1,"fieldOperator":2,"filterMode":1,"filterGroupOperator":1,"filterItems":[{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":94,"displayValue":"Flat File - MS Exchange 2003 Message Tracking Log"}],"name":"Log Source Type"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":173,"displayValue":"Flat File - MS Exchange 2007 Message Tracking Log"}],"name":"Log Source Type"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":1000211,"displayValue":"Flat File - MS Exchange 2010 Message Tracking Log"}],"name":"Log Source Type"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":1000805,"displayValue":"Flat File - MS Exchange 2016 Message Tracking Log"}],"name":"Log Source Type"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":1000561,"displayValue":"Flat File - MS Exchange 2013 Message Tracking Log"}],"name":"Log Source Type"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":1000730,"displayValue":"API - Office 365 Message Tracking"}],"name":"Log Source Type"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":1000720,"displayValue":"Flat File - Office 365 Message Tracking"}],"name":"Log Source Type"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":9,"values":[{"filterType":9,"valueType":2,"value":1000823,"displayValue":"Syslog - Open Collector - Gmail Message Tracking"}],"name":"Log Source Type"}],"name":"Filter Group"},{"filterItemType":1,"fieldOperator":1,"filterMode":1,"filterGroupOperator":0,"filterItems":[{"filterItemType":0,"fieldOperator":0,"filterMode":2,"filterType":32,"values":[{"filterType":32,"valueType":4,"value":{"value":"phishtank@phishstick.io","matchType":0},"displayValue":"phishtank@phishstick.io"}],"name":"Recipient"},{"filterItemType":1,"fieldOperator":2,"filterMode":1,"filterGroupOperator":1,"filterItems":[{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":31,"values":[{"filterType":31,"valueType":4,"value":{"value":" adelev@phishstick.io","matchType":0},"displayValue":" adelev@phishstick.io"}],"name":"Sender"},{"filterItemType":0,"fieldOperator":0,"filterMode":1,"filterType":33,"values":[{"filterType":33,"valueType":4,"value":{"value":"e-mail subject to search for!","matchType":0},"displayValue":"e-mail subject to search for!"}],"name":"Subject"}],"name":"Filter Group"}],"name":"Filter Group"}],"name":"Filter Group"}},"queryEventManager":false,"useDefaultLogRepositories":true,"dateCreated":"2021-01-26T15:53:53.7683165Z","dateSaved":"2021-01-26T15:53:53.7683165Z","dateUsed":"2021-01-26T15:54:00Z","includeDiagnosticEvents":true,"searchMode":2,"nextPageToken":"","pagedTimeout":300,"restrictedUserId":0,"createdVia":1,"searchType":1,"queryOrigin":0,"searchServerIPAddress":null,"dateCriteria":{"useInsertedDate":false,"lastIntervalValue":4,"lastIntervalUnit":4},"repositoryPattern":"","ownerId":-100,"searchId":1000000005,"queryLogSourceLists":[],"queryLogSources":[],"logRepositoryIds":[1],"refreshRate":0,"isRealTime":false,"enableIntelligentIndexing":false}' | ConvertFrom-Json
        
        #Update SOCMailbox
        $JSON.queryFilter.filterGroup.filterItems[1].filterItems[0].values.value.value = $SOCMailbox.ToLower()
        write-verbose "SOCMailbox Value: $($JSON.queryFilter.filterGroup.filterItems[1].filterItems[0].values.value.value)"
        $JSON.queryFilter.filterGroup.filterItems[1].filterItems[0].values[0].displayValue = $SOCMailbox.ToLower()
        write-verbose "SOCMailbox Display Value: $($JSON.queryFilter.filterGroup.filterItems[1].filterItems[0].values.displayValue)"

        #Update Sender
        $JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[0].values.value.value = $EmailSender.ToLower()
        write-verbose "Sender: $($JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[0].values.value.value)"
        $JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[0].values[0].displayValue = $EmailSender.ToLower()
        write-verbose "Sender Display Value: $($JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[0].values.displayValue)"

        # Update Subject
        $JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[1].values.value.value = $Subject.ToLower()
        write-verbose "Subject: $($JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[1].values.value.value)"
        $JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[1].values[0].displayValue = $Subject.ToLower()
        write-verbose "Subject Display Value: $($JSON.queryFilter.filterGroup.filterItems[1].filterItems[1].filterItems[1].values.displayValue)"



        # Establish Body Contents
        $BodyContents = $JSON | ConvertTo-Json -Depth 20

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-search-api/actions/search-task"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Send Request
        try {
            $Response = Invoke-RestAPIMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
        } catch {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Raw = $_
            $ErrorObject.Error = $true
            return $ErrorObject
        }


        return $Response
    }

    End { 
    }

}