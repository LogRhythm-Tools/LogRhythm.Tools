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
    .PARAMETER Force
        If the specified case only has a single playbook, but parameter PlaybookId does not
        match it, attempt to update that playbook anyway if a corresponding procedure can
        be found based on Id, Name, or Position.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
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
        PS C:\> Update-LrCasePlaybookProcedure -CaseId 2 -Id "Determine if you are investigating an incident or event" -Notes "This step has been completed!" -Status Completed

        id            : 5346B0E6-DF25-4181-89EB-1D7510FFE615
        name          : Determine if you are investigating an incident or event
        description   : Mark the case as an incident or event, accordingly.

        assignee      :
        status        : Completed
        dueDate       :
        notes         : This step has been completed!
        dateUpdated   : 2020-07-16T21:11:08.4773569Z
        lastUpdatedBy : @{number=2; name=LRTools; disabled=False}
    .EXAMPLE
        PS C:\> Update-LrCasePlaybookProcedure -CaseId "Mock case" -Id 1 -Notes "This step has not been completed!" -Status Notcompleted

        id            : 5346B0E6-DF25-4181-89EB-1D7510FFE615
        name          : Determine if you are investigating an incident or event
        description   : Mark the case as an incident or event, accordingly.

        assignee      :
        status        : NotCompleted
        dueDate       :
        notes         : This step has not been completed!
        dateUpdated   : 2020-07-16T21:18:52.0459919Z
        lastUpdatedBy : @{number=2; name=LRTools; disabled=False}
    .EXAMPLE
        PS C:\> Update-LrCasePlaybookProcedure -CaseId "Mock case" -Id "5346B0E6-DF25-4181-89EB-1D7510FFE615" -Notes "This step is not needed." -Status Skipped

        id            : 5346B0E6-DF25-4181-89EB-1D7510FFE615
        name          : Determine if you are investigating an incident or event
        description   : Mark the case as an incident or event, accordingly.

        assignee      :
        status        : Skipped
        dueDate       :
        notes         : This step is not needed.
        dateUpdated   : 2020-07-16T21:20:11.812571Z
        lastUpdatedBy : @{number=2; name=LRTools; disabled=False}
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


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [object] $PlaybookId,


        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2
        )]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string] $Assignee,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateLength(0,1000)]
        [string] $Notes,


        [Parameter(Mandatory = $false, Position = 5)]
        [ValidateNotNull()]
        [datetime] $DueDate,


        [Parameter( Mandatory = $false, Position = 6)]
        [ValidateSet('NotCompleted', 'Completed', 'Skipped')]
        [string] $Status,


        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $Force,


        [Parameter(Mandatory = $false, Position = 8)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
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
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $CaseId
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }


        
        #region: Identify Case Playbook to Update                                                  
        # Populate list of Case Playbooks
        $CasePlaybooks = Get-LrCasePlaybooks -Id $CaseNumber

        # Placeholder for targeted playbook to update
        $UpdatePlaybook = $null


        # Scenario: Case has no playbooks
        if (! $CasePlaybooks) {
            throw [ArgumentException] "[$Me]: No Playbooks found on case: $CaseNumber."
        }

        # Scenario: Only one playbook assigned to case
        if (($CasePlaybooks -is [array]) -and ($CasePlaybooks.Count -eq 1)) {
            # Check if PlaybookId param doesn't match
            if ((! ($PlaybookId -match $UpdatePlaybook.Id)) -and (! ($PlaybookId -match $UpdatePlaybook.Name))) {
                # Use the playbook if Force is specified, otherwise raise exception
                if ($Force) {
                    $UpdatePlaybook = $CasePlaybooks
                    $_info = "No Playbook match found for case $CaseNumber."
                    $_info += "(Force) Defaulting to only playbook $($UpdatePlaybook.Name)"
                    Write-Verbose  $_info
                } else {
                    $Err = "Case number $CaseNumber has a single playbook $($CasePlaybooks.Name), yet "
                    $Err += "$PlaybookId does not match it.  Use -Force to attempt to update it anyway."
                    throw [ArgumentException] $Err
                }
            }
        }

        # Scenario: One of the playbooks match either guid or name of $PlaybookId
        $CasePlaybooks | ForEach-Object {
            if (($_.Id -match $PlaybookId) -or ($_.Name -match $PlaybookId)) {
                $UpdatePlaybook = $_
            }
        }

        # Scenario: No matches found
        if (! $UpdatePlaybook) {
            throw [ArgumentException] "[$Me]: Case number $CaseNumber does not have a playbook matching $PlaybookId"
        }
        #endregion
        


        #region: Identify Case Procedure to Update                                                 
        # Populate list of Case Procedures
        $CaseProcedures = Get-LrCasePlaybookProcedures -CaseId $CaseNumber -Id $UpdatePlaybook.Id

        # Placeholder for targeted Procedure to update
        $UpdateProcedure = $null

        # Test Procedure $Id
        $ProcedureType = Test-LrProcedureIdFormat -Id $Id

        # Scenario: Procedure $Id is a Name or Guid - enumerate procedure to find match
        if (($ProcedureType.IsName) -or ($ProcedureType.IsGuid)) {
            $CaseProcedures | ForEach-Object {
                Write-Verbose "[$Me]: Comparing Procedure Name: $($ProcedureType.Value) To Playbook Procedure: $($_.Name) / $($_.Id)"
                if(($_.Name -match $ProcedureType.Value) -or ($_.Id -match $ProcedureType.Value)) {
                    $UpdateProcedure = $_
                }
            }
        }

        # Scenario: Procedure $Id is a procedure step #
        if ($ProcedureType.IsInt) {
            if (($Id -gt $($CaseProcedures.Count)) -Or ($Id -lt 0)) {
                throw [ArgumentException] "[$Me]: Procedure step number $Id falls outside of Procedure Count."
            } else {
                $UpdateProcedure = $CaseProcedures[($Id - 1)]
                Write-Verbose "[$Me]: Targeted procedure step $Id - $($UpdateProcedure.Name)"
            }
        }

        # Scenario: No procedure found
        if (! $UpdateProcedure) {
            throw [ArgumentException] "[$Me]: Procedure [Id:$Id] cannot be matched to any procedures for playbook $($UpdatePlaybook.Name)."
        }
        #endregion
        

        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/playbooks/$($UpdatePlaybook.Id)/procedures/$($UpdateProcedure.Id)/"

        # Inspect Date for proper format
        # Set provided EarliestEvidence Date
        if ($DueDate) {
            $DueDate = ($DueDate.ToUniversalTime()).ToString("yyyy-MM-ddTHH:mm:ssZ")
        }

        
        # Validate Assignee is valid
        if ($Assignee) {
            $AssigneeType = Test-LrUserIdFormat -Id $Assignee
            if ($AssigneeType.IsInt -eq $false) {
                $AssigneeResult = Get-LrUsers -Name $Assignee -Exact
                Write-Verbose "[$Me]: Assignee String: $Assignee Assignee Result: $($AssigneeResult.Name)"
                if ($AssigneeResult) {
                    if ($AssigneeResult.disabled -eq $true) {
                        throw [ArgumentException] "[$Me]: Parameter [Assignee:$Assignee] is currently disabled"
                    } else {
                        [int32] $AssigneeNumber = $AssigneeResult.number
                    }
                } else {
                    throw [ArgumentException] "[$Me]: Parameter [Assignee:$Assignee] not found in LrUsers"
                }
            } elseif ($AssigneeType.IsInt -eq $true) {
                $AssigneeResult = Get-LrUsers | Select-Object number, disabled | Where-Object number -eq $Assignee
                Write-Verbose "[$Me]: Assignee Int: $Assignee Assignee Result: $($AssigneeResult.Name)"
                if ($AssigneeResult) {
                    if ($AssigneeResult.disabled -eq $true) {
                        throw [ArgumentException] "[$Me]: Parameter [Assignee:$Assignee] is currently disabled"
                    } else {
                        [int32] $AssigneeNumber = $AssigneeResult.number
                    }
                } else {
                    throw [ArgumentException] "[$Me]: Parameter [Assignee:$Assignee] not found in LrUsers"
                }
            } else {
                throw [ArgumentException] "[$Me]: Parameter [Assignee] must be valid user name or user id #"
            }

            $CaseCollaborators = Get-LrCaseById -Id $CaseNumber | Select-Object -ExpandProperty collaborators
            if ($CaseCollaborators -and $AssigneeNumber) {
                if (!$CaseCollaborators.number -contains $AssigneeNumber) {
                    throw [ArgumentException] "[$Me]: Parameter [Assignee:$Assignee] not a collaborator on case $CaseNumber"
                }
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
        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"
        
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Return all responses.
        return $Response
    }

    End { }
}