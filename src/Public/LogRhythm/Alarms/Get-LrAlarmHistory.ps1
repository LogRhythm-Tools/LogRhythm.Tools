using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Get-LrAlarmHistory {
    <#
    .SYNOPSIS
        Retrieve the historical details from a specific Alarm from the LogRhythm SIEM.
    .DESCRIPTION
        Get-LrAlarmHistory returns a detailed LogRhythm Alarm object.
    .PARAMETER AlarmId
        Intiger representing the Alarm required for detail retrieval.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        
        [System.Int]           -> AlarmId
        [System.String]        -> Person
        [System.String]        -> OrderBy
        [System.String]        -> Direction
        [System.DateTime]      -> DateUpdated
        [System.String]        -> Type
        [System.Switch]        -> ResultsOnly
        [System.Int]           -> PageCount
        [PSCredential]         -> Credential
    .OUTPUTS
        PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Get-LrAlarmHistory -AlarmId 185


        alarmHistoryDetails
        -------------------
        {@{alarmId=185; personId=6; comments=Changed status to: Closed: Unresolved; dateInserted=4/16/2021 1:14:02 PM; dateUpdated=4/16/2021 1:14:02 PM}, @{alarmId=185; personId=6; comments=Changed status to: Closed: Resolve…
    .EXAMPLE
        PS C:\> Get-LrAlarmHistory -AlarmId 185 -ResultsOnly


        alarmId      : 185
        personId     : 6
        comments     : Changed status to: Closed: Unresolved
        dateInserted : 4/16/2021 1:14:02 PM
        dateUpdated  : 4/16/2021 1:14:02 PM

        alarmId      : 185
        personId     : 6
        comments     : Changed status to: Closed: Resolved
        dateInserted : 4/16/2021 1:13:51 PM
        dateUpdated  : 4/16/2021 1:13:51 PM
    .EXAMPLE
        PS C:\> Get-LrAlarmHistory -AlarmId 185 -ResultsOnly -Person 1


        alarmId      : 185
        personId     : 1
        comments     : Added to Case 80: MAC Address Observed and Changed Status to: Opened
        dateInserted : 3/31/2021 8:55:46 PM
        dateUpdated  : 3/31/2021 8:55:46 PM
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Int32] $AlarmId,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Person,


        [Parameter(Mandatory = $false, Position = 2)]
        [string] $OrderBy,


        [Parameter(Mandatory = $false, Position = 3)]
        [string] $Direction,


        [Parameter(Mandatory = $false, Position = 4)]
        [datetime] $DateUpdated,
    
        
        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateSet('comment', 'status','rbp', ignorecase=$true)]
        [string] $Type,
    

        [Parameter(Mandatory = $false, Position = 6)]
        [switch] $ResultsOnly,

        
        [Parameter(Mandatory = $false, Position = 7)]
        [int] $PageValuesCount = 1000,


        [Parameter(Mandatory = $false, Position = 8)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 9)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AlarmBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy        
    }

    Process {
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Verify version
        if ([int]$LrtConfig.LogRhythm.Version.split(".")[1] -le 6) {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.7.0 and greater."
            return $ErrorObject
        }

        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $PageValuesCount)

        # Query Offset - PageCount
        $Offset = ($PageCount -1)
        $QueryParams.Add("offset", $Offset)


        if ($DateUpdated) {
            Try {
                $RequestedTimestamp = (Get-Date $DateUpdated).ToUniversalTime()
            } Catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.Error = $true
                $ErrorObject.Raw = $_
                return $ErrorObject
            }
            
            $_dateUpdated = $RequestedTimestamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
            
            if ($_dateUpdated) {
                $QueryParams.Add("dateUpdated", $_dateUpdated)
            }
        }

        # RecordStatus
        if ($Person) {
            $_person = $Person
            $QueryParams.Add("personId", $_person)
        }

        if ($Direction) {
            switch ($Direction) {
                'ascending' {$_direction = 'ascending'}
                'descending' {$_direction = 'descending'}
                'asc' {$_direction = 'ascending'}
                'desc' {$_direction = 'descending'}
            }
            $QueryParams.Add("dir", $_direction)
        }

        # Order By
        if ($OrderBy) {
            switch ($OrderBy) {
                'alarmrulename' {$_orderBy = 'AlarmRuleName'}
                'alarmstatus' {$_orderBy = 'AlarmStatus'}
                'dateinserted' {$_orderBy = 'DateInserted'}
                'entityname' {$_orderBy = 'EntityName'}
            }
            $QueryParams.Add("orderby", $_orderBy)
        }

        # Type
        if ($Type) {
            $_type = $Type.tolower()
            $QueryParams.Add("type", $_type)
        }

        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }


        $RequestUrl = $BaseUrl + "/alarms/" + $AlarmId + "/history" + $QueryString

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        if ($Response.alarmHistoryDetails.Count -eq $PageValuesCount) {
            write-verbose "Response Count: $($Response.alarmHistoryDetails.Count)  Page Value Count: $PageValuesCount"
            $HistoryResults = [list[object]]::new()
            ForEach ($AlarmDetails in $Response.alarmHistoryDetails) {
                if ($HistoryResults.comments -notcontains $AlarmDetails.comments) {
                    $HistoryResults.Add($AlarmDetails)
                }
            }
            
            DO {
                # Increment Offset
                $Offset = $Offset + 1
                # Update Query Paramater
                $QueryParams.offset = $Offset
                # Apply to Query String
                $QueryString = $QueryParams | ConvertTo-QueryString
                # Update Query URL
                $RequestUrl = $BaseUrl + "/alarms/" + $AlarmId + "/history" + $QueryString
                # Retrieve Query Results
                try {
                    $PaginationResults = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
                } catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Code = $($Err.statusCode)
                    $ErrorObject.Note = $($Err.message)
                    $ErrorObject.Raw = $_
                    return $ErrorObject
                }
                # Append results to Response
                ForEach ($AlarmDetails in $PaginationResults.alarmHistoryDetails) {
                    if ($HistoryResults.comments -notcontains $AlarmDetails.comments) {
                        $HistoryResults.Add($AlarmDetails)
                    }
                }
                
                write-verbose "Response Count: $($PaginationResults.alarmHistoryDetails.Count)  Page Value Count: $PageValuesCount"
            } While ($($PaginationResults.alarmHistoryDetails.Count) -eq $PageValuesCount)
            #$HistoryResults = $HistoryResults | Sort-Object -Property alarmId -Unique
            $Response = [PSCustomObject]@{
                alarmHistoryDetails = $HistoryResults
                alarmsHistoryCount = $HistoryResults.Count
                statusCode = $PaginationResults.statusCode
                statusMessage = $PaginationResults.statusMessage
                responseMessage = $PaginationResults.responseMessage
            }
        }

        if ($ResultsOnly) {
            return $Response.alarmHistoryDetails
        } else {
            return $Response
        }        
    }

    End { }
}