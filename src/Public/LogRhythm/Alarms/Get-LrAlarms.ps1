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
            4/19/2021 13:00:00
            4/19/2021
            4/19/2021 3:30
    .PARAMETER OrderBy
        Field name on which the results can be sorted.

        Valid Values: AlarmRuleName, AlarmStatus, DateInserted and EntityName
    .PARAMETER Direction
        Paramater to control the results sort order direction.

        Valid Values: Asc, Desc, Ascending, Descending
    .PARAMETER Exact
        Switch used to specify Name search for Alarm Name record is explicit.  
        
        This flag can return an array of Alarms that match the exact name condition, in conjunction with any other filter criteria specified.
    .PARAMETER ResultsOnly
        Switch used to specify return only alarmSearchDetails results.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.String]       -> Name
        [System.String]       -> Entity
        [System.String]       -> AlarmStatus
        [System.String]       -> Notification
        [System.String]       -> CaseAssociation
        [System.DateTime]     -> DateInserted
        [System.String]       -> OrderBy
        [System.String]       -> Direction
        [System.Switch]       -> Exact
        [System.Switch]       -> ResultsOnly
        [PSCredential]        -> Credential
    .OUTPUTS
        PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        Get-LrAlarms
        
        alarmsSearchDetails : {@{alarmId=181; alarmRuleName=AIE: Test Rule - Calc.exe; alarmStatus=1; alarmDataCached=Y; associatedCases=System.Object[]; entityName=Global Entity; dateInserted=1/20/2021 6:26:41 PM},
                            @{alarmId=182; alarmRuleName=AIE: MAC Address Observed; alarmStatus=1; alarmDataCached=Y; associatedCases=System.Object[]; entityName=Global Entity; dateInserted=3/30/2021 3:33:36 PM},
                            @{alarmId=183; alarmRuleName=AIE: MAC Address Observed; alarmStatus=1; alarmDataCached=Y; associatedCases=System.Object[]; entityName=Global Entity; dateInserted=3/30/2021 5:56:42 PM},
                            @{alarmId=184; alarmRuleName=AIE: MAC Address Observed; alarmStatus=1; alarmDataCached=Y; associatedCases=System.Object[]; entityName=Global Entity; dateInserted=3/31/2021 8:44:00 PM}…}
        alarmsCount         : 6
        statusCode          : 200
        statusMessage       : OK
        responseMessage     : Success
    .EXAMPLE
        PS C:\> Get-LrAlarms -OrderBy AlarmRuleName -Direction desc -ResultsOnly
        
        alarmId         : 181
        alarmRuleName   : AIE: Test Rule - Calc.exe
        alarmStatus     : 1
        alarmDataCached : Y
        associatedCases : {36968FA0-C046-4B98-B0AF-03989DC63F8F}
        entityName      : Global Entity
        dateInserted    : 1/20/2021 6:26:41 PM

        alarmId         : 182
        alarmRuleName   : AIE: MAC Address Observed
        alarmStatus     : 1
        alarmDataCached : Y
        associatedCases : {B5F10081-9F85-4DEA-94A7-1668F536623B,  598BA826-0321-4B17-A45E-BB2343151AC3}
        entityName      : Global Entity
        dateInserted    : 3/30/2021 3:33:36 PM

        alarmId         : 183
        alarmRuleName   : AIE: MAC Address Observed
        alarmStatus     : 1
        alarmDataCached : Y
        associatedCases : {5E5E9EE0-EF92-4280-89F8-E64F37798B67}
        entityName      : Global Entity
        dateInserted    : 3/30/2021 5:56:42 PM
    .EXAMPLE 
        Get-LrAlarms -Name "AIE: Test Rule - Calc.exe" -ResultsOnly
        
        alarmId         : 181
        alarmRuleName   : AIE: Test Rule - Calc.exe
        alarmStatus     : 1
        alarmDataCached : Y
        associatedCases : {36968FA0-C046-4B98-B0AF-03989DC63F8F}
        entityName      : Global Entity
        dateInserted    : 1/20/2021 6:26:41 PM
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
        [ValidateSet('AlarmRuleName', 'AlarmStatus','DateInserted ', 'entityName', ignorecase=$true)]
        [string] $OrderBy = 'DateInserted',


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateSet('asc','desc', 'ascending', 'descending', ignorecase=$true)]
        [string] $Direction = "asc",


        [Parameter(Mandatory = $false, Position = 7)]
        [datetime] $DateInserted,
    

        [Parameter(Mandatory = $false, Position = 8)]
        [switch] $ResultsOnly,


        [Parameter(Mandatory = $false, Position = 9)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 10)]
        [int] $PageValuesCount = 1000,


        [Parameter(Mandatory = $false, Position = 11)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 12)]
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

        # Filter by Object Name
        if ($Exact) {
            if ($Name) {
                $_name = $Name
                $QueryParams.Add("alarmRuleName", $_name)
            }
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


        # Return results direction, ascending or descending
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

        $RequestUrl = $BaseUrl + "/lr-alarm-api/alarms" + $QueryString

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }


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
                $RequestUrl = $BaseUrl + "/lr-alarm-api/alarms" + $QueryString
                Write-Verbose "[$Me]: Request URL: $RequestUrl"
                
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if ($PaginationResults.Error) {
                    return $PaginationResults
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

        # If ResultsOnly flag is provided, return only the alarmSearchDetails.
        if ($ResultsOnly) {
            $Response = $Response.alarmsSearchDetails
        }


        if ($Name) {
            Write-Verbose "Performing Name match without exact."
            $Pattern = "^$Name.*?$"
            $NameResults = [list[object]]::new()
            if ($ResultsOnly) {
                $Response | ForEach-Object {
                    if(($_.alarmRuleName -match $Pattern) -or ($_.alarmRuleName -like $Name)) {
                        Write-Verbose "[$Me]: Name match found."
                        $NameResults.Add($_)
                    }
                }
                if ($NameResults) {
                    return $NameResults
                } else {
                    return $null
                }
            } else {
                $Response.alarmsSearchDetails | ForEach-Object {
                    if(($_.alarmRuleName -match $Pattern) -or ($_.alarmRuleName -like $Name)) {
                        Write-Verbose "[$Me]: Name match found."
                        $NameResults.Add($_)
                    }
                }
                if ($NameResults) {
                    $Response.alarmsCount = $NameResults.count
                    $Response.alarmsSearchDetails = $NameResults
                    return $Response
                } else {
                    return $null
                }
            }
        } else {
            return $Response
        }
    }

    End {
    }
}