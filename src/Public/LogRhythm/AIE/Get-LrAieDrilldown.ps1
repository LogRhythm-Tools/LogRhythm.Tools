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
        PS C:\> Get-LrAieDrilldown -Credential $token -AlarmId 2261993
        ---
        AlarmID           : System.Int32
        AlarmGuid         : System.String (guid)
        Priority          : System.Int32
        AIERuleName       : Brute Force Login Attempts
        Status            : 4
        Logs              : [System.Object]
        SummaryFields     : System.Collections.Generic.Dictionary[string,string]
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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 1
        )]
        [int] $AlarmId,


        [Parameter(Mandatory = $false, Position = 2)]
        [int] $RetryAttempts = 18,


        [Parameter(Mandatory = $false, Position = 3)]
        [int] $RetryWaitSeconds = 10
    )
    #endregion



    #region: Begin                                                                       
    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.LogRhythm.AieBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }
    #endregion



    #region: Process                                                                     
    Process {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")
        

        # Request URI   
        $Method = $HttpMethod.Get
        $RequestUrl = $BaseUrl + "/drilldown/$AlarmId/"



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
                Write-Verbose "Unable to retrieve drilldown after $RetryAttempts attempts. Aborting."
                break;
            }

            # REST Request
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod -Uri $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
                }
                catch {
                    #region Exception Handling                                               
                    $Err = Get-RestErrorMessage $_
                    $ExceptionMsg = $_.Exception.message

                    # Catch specific error corresponding to classic alarms
                    # These errors throw a WebException including a message with text:
                    # "The remote server returned an error: (404) Not Found."
                    # $Err in this case will have the proper container for data, but
                    # the results will be null. Part of the validation of this type
                    # of error is to check that the DrillDownResults property exists.
                    if (($Err.data).PSObject.Properties.name -match "DrillDownResults") {
                        if ($Err.data.DrillDownResults.Count -eq 0) {
                            $Msg = "[$Me]: (LogRhythm API) "
                            $Msg += $ExceptionMsg
                            $Msg += " When a 404 error is specified, ensure that the requested"
                            $Msg += " alarm is from an AI Engine rule and not a diagnostic alarm."
                            throw [Exception] $Msg
                        }
                    }
                    if (! $Err) {
                        # Unable to parse Rest Error, re-throw our error.
                        $PSCmdlet.ThrowTerminatingError($PSItem)
                    }
                    # We could parse the Rest Error, throw a custom error based on fields.
                    $Msg = "[$Me] [$($Err.statusCode)]: $($Err.message) | "
                    $Msg += "$($Err.details)`n$($Err.validationErrors)`n"
                    throw [Exception] $Msg                
                    #endregion
                }
            } else {
                try {
                    $Response = Invoke-RestMethod -Uri $RequestUrl -Headers $Headers -Method $Method
                }
                catch [System.Net.WebException] {
                    #region Exception Handling                                               
                    $Err = Get-RestErrorMessage $_
                    $ExceptionMsg = $_.Exception.message

                    # Catch specific error corresponding to classic alarms
                    # These errors throw a WebException including a message with text:
                    # "The remote server returned an error: (404) Not Found."
                    # $Err in this case will have the proper container for data, but
                    # the results will be null. Part of the validation of this type
                    # of error is to check that the DrillDownResults property exists.
                    if (($Err.data).PSObject.Properties.name -match "DrillDownResults") {
                        if ($Err.data.DrillDownResults.Count -eq 0) {
                            $Msg = "[$Me]: (LogRhythm API) "
                            $Msg += $ExceptionMsg
                            $Msg += " When a 404 error is specified, ensure that the requested"
                            $Msg += " alarm is from an AI Engine rule and not a diagnostic alarm."
                            throw [Exception] $Msg
                        }
                    }
                    if (! $Err) {
                        # Unable to parse Rest Error, re-throw our error.
                        $PSCmdlet.ThrowTerminatingError($PSItem)
                    }
                    # We could parse the Rest Error, throw a custom error based on fields.
                    $Msg = "[$Me] [$($Err.statusCode)]: $($Err.message) | "
                    $Msg += "$($Err.details)`n$($Err.validationErrors)`n"
                    throw [Exception] $Msg                
                    #endregion
                }
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
        $SummaryFields = [List[Dictionary[string,string]]]::new()
        foreach ($ruleBlock in $_dd.RuleBlocks) {
            $fields = [Dictionary[string,string]]::new()

            foreach ($field in $ruleBlock.DDSummaries) {
                $FieldName = $field.PIFType | Get-PIFTypeName
                $FieldValue = ($field.DrillDownSummaryLogs | ConvertFrom-Json).field
                $fields.Add($FieldName, $FieldValue)
            }
            $SummaryFields.Add($fields)
        }

        # Create Output Object
        $Return = [PSCustomObject]@{
            AlarmID = $_dd.AlarmId
            AlarmGuid = $_dd.AlarmGuid
            Priority = $_dd.Priority
            AIERuleName = $_dd.AIERuleName
            Status = $_dd.Status
            Logs = $Logs
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