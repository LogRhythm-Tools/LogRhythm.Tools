using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Get-LrAlarms {
    <#
    .SYNOPSIS
        Retrieve a list of Alarms from the LogRhythm SIEM.
    .DESCRIPTION
        Get-LrAlarms returns a full LogRhythm Alarm object, including details.
    .PARAMETER Name
        String used to search Entity Host records by Name.
    .PARAMETER Entity
        String used to search Entity Host by Entity Name.
    .PARAMETER AlarmStatus
        String value used to restrict results based on Alarm Status.

        Valid entries: 
    .PARAMETER Notification
        String used to restrict results based on Notification Groups.

        Valid entries: 
    .PARAMETER CaseAssociation
        String used to restrict results based on Case Association.

        Valid entries: 
    .PARAMETER DateInserted
        String used to restrict results based on Notification Groups.

        Valid entries: 
    .PARAMETER OrderBy
        Field name on which the results can be sorted.

        Valid Values: AlarmRuleName, AlarmStatus, DateInserted and EntityName
    .PARAMETER Exact
        Switch used to specify Name search for Entity Host record is explicit.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.Int]           -> PageCount
        [System.String]        -> Name
        [System.String]        -> Entity
        [System.String]        -> RecordStatus
        [System.String[array]] -> HostIdentifier
        [System.Switch]        -> Exact
    .OUTPUTS
        PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Get-LrAlarms
        ---

    .EXAMPLE
        Get-LrHosts -name "windows"
        ---

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Entity,


        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Alarm,


        [Parameter(Mandatory = $false, Position = 3)]
        [string] $Notification,


        [Parameter(Mandatory = $false, Position = 4)]
        [string] $CaseId,


        [Parameter(Mandatory = $false, Position = 5)]
        [datetime] $DateInserted,
    

        [Parameter(Mandatory = $false, Position = 6)]
        [switch] $Exact,


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

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LogRhythm.Version

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


        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $PageValuesCount)

        # Query Offset - PageCount
        $Offset = ($PageCount -1)
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if ($Name) {
            $_name = $Name
            $QueryParams.Add("alarmRuleName", $_name)
        }


        # Filter by Object Entity Name
        if ($Entity) {
            $_entityName = $Entity
            $QueryParams.Add("entityName", $_entityName)
        }

        if ($CaseId) {
            $CaseIdStatus = Test-LrCaseIdFormat -Id $CaseId
            if (($CaseIdStatus.IsValid -eq $true) -and ($null -ne $CaseIdStatus.CaseNumber) ) {
                $_caseId = $CaseIdStatus.CaseGuid.replace("-","")
            } else {
                $_caseId = $CaseId
            }
            $QueryParams.Add("caseAssociation", $_caseId)
        }

        if ($DateInserted) {
            Try {
                $RequestedTimestamp = (Get-Date $DateInserted).ToUniversalTime()
            } Catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err.message
                $ErrorObject.Error = $true
                $ErrorObject.Raw = $_
                return $ErrorObject
            }
            
            $_dateInserted = $RequestedTimestamp.ToString("yyyy-MM-ddTHH:mm:ssZ")
            
            if ($_dateInserted) {
                $QueryParams.Add("dateInserted", $_dateInserted)
            }
        }


        # RecordStatus
        if ($AlarmStatus) {
            $_alarmStatus = $AlarmStatus.ToLower()
            $QueryParams.Add("alarmStatus", $_alarmStatus)
        }


        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }
        #endregion

        $RequestUrl = $BaseUrl + "/alarms" + $QueryString

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
        write-host $Response


        if ($Response.alarmsCount -eq $PageValuesCount) {
            write-verbose "Response Count: $($Response.alarmsCount)  Page Value Count: $PageValuesCount"
            $AlarmResults = [list[object]]::new()
            ForEach ($AlarmDetails in $Response.alarmSearchDetails) {
                if ($AlarmResults.alarmId -notcontains $AlarmDetails.alarmId) {
                    $AlarmResults.Add($AlarmDetails)
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
                $RequestUrl = $BaseUrl + "/alarms" + $QueryString
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
                ForEach ($AlarmDetails in $PaginationResults.alarmsSearchDetails) {
                    if ($AlarmResults.alarmId -notcontains $AlarmDetails.alarmId) {
                        $AlarmResults.Add($AlarmDetails)
                    }
                }
                
                write-verbose "Response Count: $($PaginationResults.alarmsCount)  Page Value Count: $PageValuesCount"
            } While ($($PaginationResults.alarmsCount) -eq $PageValuesCount)
            #$AlarmResults = $AlarmResults | Sort-Object -Property alarmId -Unique
            $Response = [PSCustomObject]@{
                alarmsSearchDetails = $AlarmResults
                alarmsCount = $AlarmResults.Count
                statusCode = $PaginationResults.statusCode
                statusMessage = $PaginationResults.statusMessage
                responseMessage = $PaginationResults.responseMessage
            }
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