using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrAlarmToCase {
    <#
    .SYNOPSIS
        Add one or more alarms to a LogRhythm case.
    .DESCRIPTION
        The Add-LrAlarm to case cmdlet adds one or more alarms to
        a LogRhythm case.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        The Id of the case for which to add alarms.
    .PARAMETER AlarmNumbers
        The Id of the alarms to add to the provided Case Id.
    .INPUTS
        System.Int32[] -> AlarmNumbers
    .OUTPUTS
        The updated [LrCase] object.
    .EXAMPLE
        PS C:\> Add-LrAlarmToCase -id 2 -AlarmNumbers 7
        ---

        id                      : 408C2E88-2E5D-4DA5-90FE-9F4D63B5B709
        number                  : 2
        externalId              :
        dateCreated             : 2020-06-06T13:46:49.4964154Z
        dateUpdated             : 2020-07-17T01:36:37.1633333Z
        dateClosed              :
        owner                   : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy           : @{number=-100; name=LogRhythm Administrator; disabled=False}
        name                    : Case 2
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-06-07T13:46:44Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 :
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=-100; name=LogRhythm Administrator; disabled=False}, @{number=1; name=lrtools; disabled=False}}
    .EXAMPLE
        PS C:\> Add-LrAlarmToCase -id "Case 2" -AlarmNumbers 6
        ---

        id                      : 408C2E88-2E5D-4DA5-90FE-9F4D63B5B709
        number                  : 2
        externalId              :
        dateCreated             : 2020-06-06T13:46:49.4964154Z
        dateUpdated             : 2020-07-17T01:39:28.9133333Z
        dateClosed              :
        owner                   : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy           : @{number=-100; name=LogRhythm Administrator; disabled=False}
        name                    : Case 2
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-06-07T13:46:44Z
        resolution              :
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 :
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=-100; name=LogRhythm Administrator; disabled=False}, @{number=1; name=lrtools; disabled=False}}
        tags                    : {}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [int[]] $AlarmNumbers,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $PassThru,

        
        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )


    #region: BEGIN                                                                       
    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
                                                      
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Request URI
        $Method = $HttpMethod.Post
    }
    #endregion

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Case                  =   $Id
            Code                  =   $null
            Error                 =   $false
            Note                  =   $null
            Type                  =   $null
            Raw                   =   $null
        }


        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }


        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/evidence/alarms/"
        #endregion

        #region: Request Body                                                            
        # Request Body - ensure we always pass an array per API spec
        if (! ($AlarmNumbers -Is [System.Array])) {
            $AlarmNumbers = @($AlarmNumbers)
        }
        # Convert to Json
        $Body = [PSCustomObject]@{
            alarmNumbers = $AlarmNumbers
        } | ConvertTo-Json
        Write-Verbose "[$Me] Request Body:`n$Body"
        #endregion



        #region: Send Request                                                            
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Error = $true
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        # The response is an array of alarms added to the case
        $AddedAlarms = $Response
        Write-Verbose "Added $($AddedAlarms.Count) alarms to case."        
        #endregion


        # Done!
        if ($PassThru) {
            #region: Get Updated Case                                                        
            Write-Verbose "[$Me] Getting Updated Case"
            $UpdatedCase = Get-LrCaseById -Id $CaseNumber    

            return $UpdatedCase
        }
    }
        #endregion


    End { }
}