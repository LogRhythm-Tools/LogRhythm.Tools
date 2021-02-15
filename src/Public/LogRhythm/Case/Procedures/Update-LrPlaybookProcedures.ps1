using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrPlaybookProcedures {
    <#
    .SYNOPSIS
        Apply updates to a LogRhythm playbook's procedures.
    .DESCRIPTION
        Add, update, remove, or reorder playbook procedures. The procedures specified in the request body will replace all existing procedures for the playbook.

        Any existing procedure that is not listed in the request body will be removed.

        The order of the list in the request body will become the procedure order.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Id or Name of the existing playbook.
    .PARAMETER Procedure01
        Object representing all data required for the First Procedure.

        Object structure:
        @{ 
            name = Name of the procedure, 
            description = Detailed information on the procedure, 
            dueWithinSeconds = Duration in seconds it is due after attached to a case
        }

        id - Nullable field that does not need to be presented.
        Name - String limited to 150 characters.
        Description - String limited to 4000 characters.
        dueWithinSeconds - Integer limited to range 0 - 31536000.  Default: 0
    .PARAMETER Procedure02
        Reference Procedure01 notes.
    .PARAMETER Procedure03
        Reference Procedure01 notes.
    .PARAMETER Procedure04
        Reference Procedure01 notes.
    .PARAMETER Procedure05
        Reference Procedure01 notes.
    .PARAMETER Procedure06
        Reference Procedure01 notes.
    .PARAMETER Procedure07
        Reference Procedure01 notes.
    .PARAMETER Procedure08
        Reference Procedure01 notes.
    .PARAMETER Procedure09
        Reference Procedure01 notes.
    .PARAMETER Procedure10
        Reference Procedure01 notes.
    .PARAMETER Procedure11
        Reference Procedure01 notes.
    .INPUTS
        [System.Object] "Id" ==> [Id] : The ID of the Case to modify.
    .OUTPUTS
        PSCustomObject representing the added playbook.
    .EXAMPLE
        PS C:\> Update-LrProcedure
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Id,

        [Parameter(Mandatory = $false, Position = 1)]
        [object] $Procedure01,

        [Parameter(Mandatory = $false, Position = 2)]
        [object] $Procedure02,

        [Parameter(Mandatory = $false, Position = 3)]
        [object] $Procedure03,

        [Parameter(Mandatory = $false, Position = 4)]
        [object] $Procedure04,

        [Parameter(Mandatory = $false, Position = 5)]
        [object] $Procedure05,

        [Parameter(Mandatory = $false, Position = 6)]
        [object] $Procedure06,

        [Parameter(Mandatory = $false, Position = 7)]
        [object] $Procedure07,

        [Parameter(Mandatory = $false, Position = 8)]
        [object] $Procedure08,

        [Parameter(Mandatory = $false, Position = 9)]
        [object] $Procedure09,

        [Parameter(Mandatory = $false, Position = 10)]
        [object] $Procedure10,

        [Parameter(Mandatory = $false, Position = 12)]
        [object[]] $BulkProcedures,

        [Parameter(Mandatory = $false, Position = 13)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )


    Begin {
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = $LrtConfig.LogRhythm.CaseBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Request URI
        $Method = $HttpMethod.Put
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Id
            Raw                   =   $null
        }

        # List of Procedures for Processing
        $Procedures = [List[object]]::new()

        # Validate Playbook Ref
        $Guid = Test-Guid -Guid $Id
        if ($Guid -eq $true) {
            $Pb = Get-LrPlaybookById -Id $Id
            if ($Pb.Error -eq $true) {
                return $Pb
            }
        } else {
            $Pb = Get-LrPlaybooks -Name $Id -Exact
            if (!$Pb.Name -eq $Id) {
                $ErrorObject.Code = "404"
                $ErrorObject.Error = $true
                $ErrorObject.Type = "Null"
                $ErrorObject.Note = "Playbook does not exist."
                return $ErrorObject
            }
        }

        
        # Empty Procedure Object


        # Determine count of input paramaters
        if ($BulkProcedures) {
            ForEach ($BulkProcedure in $BulkProcedures) { 
                $Procedure = [PSCustomObject]@{
                    name = $BulkProcedure.Name
                    description = $BulkProcedure.description
                    dueWithinSeconds = $BulkProcedure.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
        } else {
            $InputProcedureCount = 0
            if ($Procedure01) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure01.Name
                    description = $Procedure01.description
                    dueWithinSeconds = $Procedure01.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure02) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure02.Name
                    description = $Procedure02.description
                    dueWithinSeconds = $Procedure02.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure03) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure03.Name
                    description = $Procedure03.description
                    dueWithinSeconds = $Procedure03.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure04) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure04.Name
                    description = $Procedure04.description
                    dueWithinSeconds = $Procedure04.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure05) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure05.Name
                    description = $Procedure05.description
                    dueWithinSeconds = $Procedure05.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure06) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure06.Name
                    description = $Procedure06.description
                    dueWithinSeconds = $Procedure06.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure07) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure07.Name
                    description = $Procedure07.description
                    dueWithinSeconds = $Procedure07.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure08) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure08.Name
                    description = $Procedure08.description
                    dueWithinSeconds = $Procedure08.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure09) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure09.Name
                    description = $Procedure09.description
                    dueWithinSeconds = $Procedure09.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
            if ($Procedure10) { 
                $InputProcedureCount += 1
                $Procedure = [PSCustomObject]@{
                    name = $Procedure10.Name
                    description = $Procedure10.description
                    dueWithinSeconds = $Procedure10.dueWithinSeconds
                }
                $Procedures.Add($Procedure)
            }
        }

        $RequestUrl = $BaseUrl + "/playbooks/$($Pb.id)/procedures/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        Write-Verbose "Procedures: $Procedures"
        # Request Body
        $Body = @($Procedures) | ConvertTo-Json
        Write-Verbose "[$Me]: Body: $Body"


        # Request
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

        return $Response
    }


    End { }
}