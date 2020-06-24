using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Update-LrCasePlaybookProcedure {
    <#
    .SYNOPSIS
        Update a procedure on a playbook on a case.
    .DESCRIPTION
        The Update-LrCasePlaybookProcedure cmdlet enables updating the status, owner, duedate, or notes
        associated with a procedure within a given playbook assigned to an open case.

        For example, update the due date or status of a procedure.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER CaseId
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER PlaybookId
        Unique identifier for the playbook as an RFC 4122 formatted string, or as the playbook name.
    .PARAMETER Id
        Unique identifier for the procedure, either as an RFC 4122 formatted string or as an integer.
    .PARAMETER Assignee
        Unique, numeric identifier, or user name, for the person to which procedure is assigned.
    .PARAMETER Notes
        Notes about the procedure.  <= 1000 characters
    .PARAMETER DueDate
        When the procedure is due, as an RFC 3339 formatted string.
    .PARAMETER Status
        Status of the procedure.  Valid Values: "NotCompleted" "Completed" "Skipped" 
    .INPUTS
        [System.Object]   ->  CaseId
        [System.Object]   ->  PlaybookId
        [System.Object]   ->  Id
        [System.String]   ->  Assignee
        [System.String]   ->  Notes
        [System.DateTime] ->  DueDate
        [System.String]   ->  Status
    .OUTPUTS
        System.Object representing the returned LogRhythm playbook procedures on the applicable case.

    .EXAMPLE
        PS C:\> Update-LrCasePlaybookProcedure -Credential $Token -CaseId "F47CF405-CAEC-44BB-9FDB-644C33D58F2A"

    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [object] $CaseId,

        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [object] $PlaybookId,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [object] $Id,

        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateNotNullOrEmpty()]
        [string] $Assignee,

        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNullOrEmpty()]
        [string] $Notes,

        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullOrEmpty()]
        [datetime] $DueDate,

        [Parameter( Mandatory = $false, Position = 7)]
        [ValidateNotNullOrEmpty()]
        [string] $Status
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
    
        # Request Method
        $Method = $HttpMethod.Put
    }


    Process {
        # Get Case Id
        $IdInfo = Test-LrCaseIdFormat $CaseId
        if (! $IdInfo.IsValid) {
            throw [ArgumentException] "Parameter [Id] should be an RFC 4122 formatted string or an integer."
        } else {
            # Convert CaseID Into to Guid
            if ($IdInfo.IsGuid -eq $false) {
                # Retrieve Case Guid
                $CaseGuid = (Get-LrCaseById -Id $CaseId).id
            } else {
                $CaseGuid = $CaseId
            }
        }

        

        # Populate list of Case Playbooks
        $CasePlaybooks = Get-LrCasePlaybooks -Id $CaseGuid

        # Validate or Retrieve Playbook Id
        if ($PlaybookId) {
            if ($null -eq $CasePlaybooks) {
                throw [ArgumentException] "No Playbooks located on case: $CaseId."
            } else {
                # Step through array of Playbooks assigned to case looking for match
                $CasePlaybooks | ForEach-Object {
                    Write-Verbose "[$Me]: $($_.Name) compared to $($PlaybookId)"
                    if (Test-Guid $PlaybookId) {
                        if($($_.Id).ToLower() -eq $PlaybookId.ToLower()) {
                            Write-Verbose "[$Me]: Matched Playbook Guid: $PlaybookId To Id: $($_.Id)"
                            $PlaybookGuid = $_.Id
                        }
                    } else {
                        if($($_.Name).ToLower() -eq $PlaybookId.ToLower()) {
                            Write-Verbose "[$Me]: Matched Playbook Name: $PlaybookId To Id: $($_.Id)"
                            $PlaybookGuid = $_.Id
                        }
                    }
                } 
                if ($null -eq $PlaybookGuid) {
                    throw [ArgumentException] "Parameter [PlayBookId:$PlaybookId] cannot be matched to playbooks on case: $CaseId."
                }
            }
        } else {
            # No matches.  Only one playbook assigned to case.  Default to single Playbook assigned to case
            if (($CasePlaybooks).Count -ge 2) {
                throw [ArgumentException] "No Playbook specified.  More than one playbook assigned to case: $CaseId."
            } elseif ($CasePlaybooks) {
                $PlaybookGuid = $CasePlaybooks.Id
                Write-Verbose "[$Me]: No Playbook specified.  One Playbook on case, applying PlaybookId: $PlaybookId"
            }
        }

        # Populate list of Case Procedures
        $CaseProcedures = Get-LrCasePlaybookProcedures -CaseId $CaseId -Id $PlaybookGuid

        # Validate or Retrieve Procedure Id
        if ($Id) {
            $ProcedureType = Test-LrProcedureIdFormat -Id $Id
            $CaseProcedures | ForEach-Object {
                Write-Verbose "[$Me]: $($_.Name) compared to $($Id)" 
                if (($ProcedureType.isguid -eq $false) -and ($ProcedureType.isint -eq $false)) {
                    # Looking for procedure by the procedure name
                    if($($_.Name).ToLower() -eq $Id.ToLower()) {
                        Write-Verbose "[$Me]: Matched Procedure Name: $Id To PlaybookId: $($_.Id)"
                        $ProcedureGuid = $_.Id
                    }
                } elseif (($ProcedureType.isguid -eq $true) -and ($ProcedureType.isint -eq $false)) {
                    #Looking for procedure by procedure guid
                    if($($_.Id).ToLower() -eq $Id.ToLower()) {
                        Write-Verbose "[$Me]: Matched Procedure Guid: $Id To PlaybookId: $($_.Id)"
                        $ProcedureGuid = $_.Id
                    }
                }
            }
            if (($ProcedureType.isguid -eq $false) -and ($ProcedureType.isint -eq $true)) {
                # Setting the procedure to the integer position/step count
                if (($Id -gt $($CaseProcedures.Count)) -Or ($Id -lt 0)) {
                    throw [ArgumentException] "Parameter [Id:$Id] as integer falls outside of Procedure Count."
                } else {
                    $ProcedureGuid = $CaseProcedures[($Id - 1)].Id
                    Write-Verbose "[$Me]: Marking procedure step $Id as $ProcedureGuid."
                }
            }
            if ($null -eq $ProcedureGuid) {
                throw [ArgumentException] "Parameter [Id:$Id] cannot be matched to playbooks on case: $CaseId."
            }
        } else {
            throw [ArgumentException] "Parameter [Id] must be provided for applicable Procedure ID."
        }
        
        # Request URI
        $RequestUrl = $BaseUrl + "/cases/$CaseGuid/playbooks/$PlaybookGuid/procedures/$ProcedureGuid/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # Inspect Note for Procedure Limitation
        if ($Notes) {
            if ($Notes.Length -gt 1000) {
                throw [ArgumentException] "Parameter [Notes] exceeded length limit.  1000:$($Notes.Length)"
            }
        }

        # Inspect Date for proper format
        # Set provided EarliestEvidence Date
        if ($DueDate) {
            Try {
                $RequestedTimestamp = (Get-Date $DueDate).ToUniversalTime()
                $NewDueDate = ($RequestedTimestamp.ToString("yyyy-MM-ddTHH:mm:ssZ"))
            }
            Catch {
                throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) - $($Err.details) - $($Err.validationErrors)"
            }
        }

        # Validate Status is proper
        if ($Status) {
            $ValidStatus = @("notcompleted", "completed", "skipped")
            
            if ($ValidStatus.Contains($Status.ToLower())) {
                Switch ($Status.ToLower())
                {
                 notcompleted { $Status = "NotCompleted" }
                 completed { $Status = "Completed" }
                 skipped { $Status = "Skipped" }
                }
            } else {
                throw [ArgumentException] "Parameter [Status] should be: NotCompleted, Completed, or Skipped."
            }
        }

        # Validate Assignee is valid
        if ($Assignee) {
            $AssigneeType = Test-LrUserIdFormat -Id $Assignee
            if ($AssigneeType.IsInt -eq $false) {
                $AssigneeResult = Get-LrUsers -Name $Assignee
                Write-Verbose "[$Me]: Assignee String: $Assignee Assignee Result: $($AssigneeResult.Name)"
                if ($AssigneeResult) {
                    if ($AssigneeResult.disabled -eq $true) {
                        throw [ArgumentException] "Parameter [Assignee:$Assignee] is currently disabled"
                    } else {
                        [int32] $AssigneeNumber = $AssigneeResult.number
                    }
                } else {
                    throw [ArgumentException] "Parameter [Assignee:$Assignee] not found in LrUsers"
                }
            } elseif ($AssigneeType.IsInt -eq $true) {
                $AssigneeResult = Get-LrUsers | Select-Object number, disabled | Where-Object number -eq $Assignee
                Write-Verbose "[$Me]: Assignee Int: $Assignee Assignee Result: $($AssigneeResult.Name)"
                if ($AssigneeResult) {
                    if ($AssigneeResult.disabled -eq $true) {
                        throw [ArgumentException] "Parameter [Assignee:$Assignee] is currently disabled"
                    } else {
                        [int32] $AssigneeNumber = $AssigneeResult.number
                    }
                } else {
                    throw [ArgumentException] "Parameter [Assignee:$Assignee] not found in LrUsers"
                }
            } else {
                throw [ArgumentException] "Parameter [Assignee] must be valid user name or user id #"
            }

            $CaseCollaborators = Get-LrCaseById -Id $CaseId | Select-Object collaborators -ExpandProperty collaborators
            if (!$CaseCollaborators.number.Contains($AssigneeNumber)) {
                throw [ArgumentException] "Parameter [Assignee:$Assignee] not a collaborator on case $CaseId"
            }
        }

        # Request Body
        $Body = [PSObject]@{}
        if ($Assignee) {
            $Body | Add-Member -NotePropertyName assignee -NotePropertyValue $AssigneeNumber
        }
        if ($Notes) {
            $Body | Add-Member -NotePropertyName notes -NotePropertyValue $Notes
        }
        if ($DueDate) {
            $Body | Add-Member -NotePropertyName dueDate -NotePropertyValue $NewDueDate
        }
        if ($Status) {
            $Body | Add-Member -NotePropertyName status -NotePropertyValue $Status
        }
        $Body = $Body | ConvertTo-Json
        
        # REQUEST
        Write-Verbose "[$Me]: request body is:`n$Body"
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_

                switch ($Err.statusCode) {
                    "404" {
                        throw [KeyNotFoundException] `
                            "[404]: Case ID $CaseId or Playbook ID $PlaybookId not found, or you do not have permission to view it."
                     }
                     "401" {
                         throw [UnauthorizedAccessException] `
                            "[401]: Credential '$($Credential.UserName)' is unauthorized to access 'lr-case-api'"
                     }
                    Default {
                        throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) - $($Err.details) - $($Err.validationErrors)"
                    }
                }
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_

                switch ($Err.statusCode) {
                    "404" {
                        throw [KeyNotFoundException] `
                            "[404]: Case ID $CaseId or Playbook ID $PlaybookId not found, or you do not have permission to view it."
                     }
                     "401" {
                         throw [UnauthorizedAccessException] `
                            "[401]: Credential '$($Credential.UserName)' is unauthorized to access 'lr-case-api'"
                     }
                    Default {
                        throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) - $($Err.details) - $($Err.validationErrors)"
                    }
                }
            }
        }

        # Return all responses.
        return $Response
    }

    End { }
}