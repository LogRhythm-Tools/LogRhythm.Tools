using namespace System
using namespace System.Collections.Generic
using namespace System.Diagnostics

Function Get-LrAieDrilldown {
    <#
    .SYNOPSIS
        Get AIE Drilldown results for a LogRhythm Alert.
    .DESCRIPTION
        The Get-LrAieDrilldown cmdlet retrieves drilldown results
        (logs) associated with a LogRhythm Alarm.
        In some cases it may take several minutes for an alarm to be
        updated with drilldown logs. When executing Get-LrAieDrilldown
        from a SmartResponse action, drilldown data may not be available
        for a short time while the Drilldown Cache Service is in the 
        process of getting logs from data indexers.
        To mitigate this, Get-LrAieDrilldown will reattempt the request 
        (18) times, waiting (10 seconds) between each attempt. These
        values can be modified by speciftying the RetryAttempts and
        RetryWaitSeconds parameters. This should be sufficient for the
        majority of alarms unless the platform is under heavy load.
        **Note** Legacy Alarm Rule (diagnostic events) are not
        supported by the LogRhythm Drilldown Cache API. These alarms
        will return a 404 if requested.
        https://community.logrhythm.com/t5/AI-Engine-Rules/AIE-Drilldown-API/m-p/44276#M1295%C2%A0
    .PARAMETER Credential
        [PSCredential] containing an API Token in the Password field.
        **Note**
        The Credential parameter can be omitted if a [PSCredential]
        containing the LogRhythm Bearer Token is set to the preference
        variable $LrtConfig.LogRhythm.ApiKey.
    .PARAMETER AlarmId
        The Id of the LogRhythm Alarm.
    .PARAMETER RetryAttempts
        The number of times to attempt to retrieve the alarm drilldown.
    .PARAMETER RetryWaitSeconds
        The number of seconds to wait between attempts.
    .INPUTS
        System.Int32 -> AlarmId
    .OUTPUTS
        PSCustomObject representing the Drilldown results.
    .EXAMPLE
        PS C:\> Get-LrAieDrilldown -AlarmId 2261993
        ---
        AlarmID           : System.Int32
        AlarmGuid         : System.String (guid)
        Priority          : System.Int32
        AIERuleName       : Brute Force Login Attempts
        Status            : 4
        Logs              : [System.Object]
        SummaryFields     : [System.Object]
        NotificationSent  : System.Boolean
        EventID           : 1955438337
        NormalMessageDate : System.Date
        AIEMsgXml         : System.String (xml content)
    .NOTES
        As of LogRhythm 7.4.9 the AIE Drilldown API is still
        under development, but this cmdlet has been thoroughly tested
        in development and production environments and used in hundreds
        of SmartResponse actions.
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    #region: Parameters                                                                  
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [int] $AlarmId,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [int] $RetryAttempts = 18,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [int] $RetryWaitSeconds = 10,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )
    #endregion



    #region: Begin                                                                       
    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }
    #endregion



    #region: Process                                                                     
    Process { 
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            Code                  =   $null
            Type                  =   $null
            Raw                   =   $null
        }

        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "/lr-drilldown-cache-api/drilldown/$AlarmId/"


        #region: Request Loop                                                            
        # Timer / Loop Setup
        $DrilldownWatch = [Stopwatch]::StartNew()
        $DrilldownComplete = $false
        $Attempts = 0

        # Request Loop
        while (! $DrilldownComplete) {
            # Track #attempts
            $Attempts++

            # If we've hit our limit of attempts, exit the loop.
            if ($Attempts -gt $RetryAttempts) {
                Write-Verbose "Unable to retrieve drilldown after $RetryAttempts attempts.  Aborting."
                $DrilldownWatch.Stop()
                $ErrorObject.Error = $true
                $ErrorOBject.Note = "Unable to retrieve drilldown after $RetryAttempts attempts over $([math]::Round($($DrilldownWatch.Elapsed.TotalSeconds),2)) seconds."
                $ErrorObject.Type = 'Timeout'
                $ErrorObject.Code = 408
                return $ErrorObject
            }

            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
            if ($Response.Error) {
                return $Response
            }

            # Wait X seconds if no result
            if (! $Response.Data.DrillDownResults) {
                Write-Verbose "Drilldown not found, waiting $RetryWaitSeconds seconds."
                Start-Sleep -Seconds $RetryWaitSeconds
            } else {
                $DrilldownComplete = $true
                $DrilldownWatch.Stop()
                Write-Verbose "Drilldown succesfully retrieved."
                Write-Verbose "Seconds elapsed: $($DrilldownWatch.Elapsed.TotalSeconds)"
            }
        }
        #endregion


        #region: Prorcess Result                                                         
        # Shortcut to the meat of the response:
        $_dd = $Response.Data.DrillDownResults
        
        # Get Logs
        $Logs = [List[Object]]::new()
        foreach ($ruleBlock in $_dd.RuleBlocks) {
            $ddLogs = $ruleBlock.DrillDownLogs | ConvertFrom-Json
            $ddLogs | ForEach-Object { $Logs.Add($_) }
        }

        # Get Summary Fields
        $SummaryFields = [List[object]]::new()
        foreach ($ruleBlock in $_dd.RuleBlocks) {
            foreach ($field in $ruleBlock.DDSummaries) {
                $fields = [PSCustomObject]@{
                    FieldName = $($field.PIFType | Get-PIFTypeName)
                    FieldValue = ($field.DrillDownSummaryLogs | ConvertFrom-Json).field
                    FieldCount = ($field.DrillDownSummaryLogs | ConvertFrom-Json).value
                }
                $SummaryFields.Add($fields)
            }

        }

        # Create Output Object
        $Return = [PSCustomObject]@{
            AlarmID = $_dd.AlarmId
            AlarmGuid = $_dd.AlarmGuid
            Priority = $_dd.Priority
            AIERuleName = $_dd.AIERuleName
            AIERuleID = $_dd.AIERuleID
            AIEDrilldownRetryCount = $_dd.RetryCount
            Status = $_dd.Status
            Logs = $Logs
            LogCount = $Logs.count
            SummaryFields = $SummaryFields
            NotificationSent = $_dd.NotificationSent
            EventID = $_dd.EventID
            NormalMessageDate = $_dd.NormalMessageDate
            AIEMsgXml = $_dd.AIEMsgXml
        }
        #endregion


        # Done!
        return $Return
    }
    #endregion

    End { }
}