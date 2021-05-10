using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCasePlaybookProcedures {
    <#
    .SYNOPSIS
        Return a list of procedures on a playbook on a case.
    .DESCRIPTION
        The Get-LrCasePlaybookProcedures cmdlet returns a list of procedures associated
        with a playbook that has been assigned to a specific case.

        If no Id is specified and only one playbook is assigned, that playbook's procedures will be returned.
    .PARAMETER CaseId
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER Id
        (Optional) Unique identifier for the playbook, either as an RFC 4122 formatted string, or as a string.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .INPUTS
        [System.Object]   ->  CaseId
        [System.Object]   ->  Id
    .OUTPUTS
        System.Object representing the returned LogRhythm playbook procedures on the applicable case.

        If no prceodures are found, this cmdlet will return null.
    .EXAMPLE
        PS C:\> Get-LrCasePlaybookProcedures -CaseId 8703 -Id "4CAB940D-CFF7-442E-A54A-5D4949FA783D"
        ---
        id            : C8C47BEC-7E77-44C0-AB7A-3DFA2AF6E9FF
        name          : Drill down on the alarm to gain additional insight
        description   :
        assignee      :
        status        : NotCompleted
        dueDate       :
        notes         :
        dateUpdated   : 2019-12-23T13:36:04.3544575Z
        lastUpdatedBy : @{number=227; name=Domo, Derby; disabled=False}

        id            : 1900E73A-B1C2-4C76-95C4-5E251C7E3BC6
        name          : Determine if the event is an incident
        description   :
        assignee      :
        status        : NotCompleted
        dueDate       :
        notes         :
        dateUpdated   : 2019-12-23T13:36:04.3544575Z
        lastUpdatedBy : @{number=227; name=Domo, Derby; disabled=False}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $CaseId,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")
        

        # Request Method
        $Method = $HttpMethod.Get

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy        
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Case                  =   $Id
            Raw                   =   $null
        }
        
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $CaseId
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }
        

        # Populate list of Case Playbooks
        $CasePlaybooks = Get-LrCasePlaybooks -Id $CaseNumber

        # Validate or Retrieve Playbook Id
        if ($Id) {
            if ($null -eq $CasePlaybooks) {
                throw [ArgumentException] "No Playbooks located on case: $CaseNumber."
            } else {
                # Validate Playbook Id
                # Step through array of Playbooks assigned to case looking for match
                $CasePlaybooks | ForEach-Object {
                    Write-Verbose "[$Me]: $($_.Name) compared to $($Id)"
                    if (Test-Guid $Id) {
                        if($($_.Id).ToLower() -eq $Id.ToLower()) {
                            Write-Verbose "[$Me]: Matched Playbook Guid: $Id To Id: $($_.Id)"
                            $PlaybookGuid = $_.Id
                        } 
                    } else {
                        if($($_.Name).ToLower() -eq $Id.ToLower()) {
                            Write-Verbose "[$Me]: Matched Playbook Name: $Id To Id: $($_.Id)"
                            $PlaybookGuid = $_.Id
                        }
                    }
                }
                if ($null -eq $PlaybookGuid) {
                    throw [ArgumentException] "Parameter [Id:$Id] cannot be matched to playbooks on case: $CaseId."
                }
            }
        } else {
            # No matches.  Only one playbook assigned to case.  Default to single Playbook assigned to case
            if (($CasePlaybooks).Count -ge 2) {
                throw [ArgumentException] "No Playbook specified.  More than one playbook assigned to case: $CaseId."
            } elseif ($CasePlaybooks) {
                $PlaybookGuid = $CasePlaybooks.Id
                Write-Verbose "[$Me]: No Playbook specified.  One Playbook on case, applying Id: $Id"
            }
        }
        

        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/playbooks/$PlaybookGuid/procedures/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # REQUEST
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err.message
            $ErrorObject.Error = $true
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        # Return all responses.
        return $Response
    }


    End { }
}