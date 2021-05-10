using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Add-LrAlarmComment {
    <#
    .SYNOPSIS
        Add a new comment to a specific Alarm from the LogRhythm SIEM.
    .DESCRIPTION
        Add-LrAlarmComment returns a status message indicating the results of the Add Comment service.
    .PARAMETER AlarmId
        Intiger representing the Alarm required for detail retrieval.
    .PARAMETER Comment
        String value representing the comment being added to the Alarm.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS
        [System.Int]           -> AlarmId
        [System.String]        -> Comment
        [System.Switch]        -> PassThru
        [PSCredential]         -> Credential
    .OUTPUTS
        By defaul the output is null unless an error is generated.
        
        With the PassThru switch a PSCustomObject representing LogRhythm Alarms and their contents.
    .EXAMPLE
        PS C:\> Add-LrAlarmComment -AlarmId 185 -Comment "Here is my new comment!"

    .EXAMPLE
        PS C:\> Add-LrAlarmComment -AlarmId 185 -Comment "Here is my new comment!" -PassThru


        statusCode statusMessage responseMessage
        ---------- ------------- ---------------
            201 OK            Comment added successfully
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [Int32] $AlarmId,


        [Parameter(Mandatory = $true, Position = 1)]
        [String] $Comment,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru,


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
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post

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

        $_comment = $Comment

        $BodyContents = [PSCustomObject]@{
            alarmComment = $_comment
        }

        # Establish Body Contents
        $Body = $BodyContents | ConvertTo-Json

        Write-Verbose "$Body"


        $RequestUrl = $BaseUrl + "/lr-alarm-api/alarms/" + $AlarmId + "/comment"

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }


        if ($PassThru) {
            return $Response
        }
    }

    End { }
}