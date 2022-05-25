using namespace System
using namespace System.Collections.Generic
using namespace System.Diagnostics

Function Get-LrAieSummary {
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
        

        $Method = $HttpMethod.Get

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }
    #endregion



    #region: Process                                                                     
    Process {
        # Request URI   
        $RequestUrl = $BaseUrl + "/lr-drilldown-cache-api/drilldown/$AlarmId/summary"
     
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }
        
        #region: Prorcess Result                                                         
        # Shortcut to the meat of the response:
        $_dd = $Response.Data.drilldownsummary

        # Get Summary Fields
        $SummaryFields = [List[Dictionary[string,string]]]::new()
        foreach ($ruleBlock in $_dd.RuleBlocks) {
            $fields = [Dictionary[string,string]]::new()

            foreach ($field in $ruleBlock.DDSummaries) {
                $FieldName = $field.PIFType
                $FieldValue = ($field.DrillDownSummaryLogs | ConvertFrom-Json).field
                $fields.Add($FieldName, $FieldValue)
            }
            $SummaryFields.Add($fields)
        }

        # Done!
        return $SummaryFields 
    }
    #endregion

    End { }
}