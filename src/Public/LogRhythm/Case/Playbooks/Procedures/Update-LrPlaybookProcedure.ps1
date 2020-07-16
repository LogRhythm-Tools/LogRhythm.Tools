using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrPlaybookProcedure {
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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Id,

        [Parameter(Mandatory = $false, Position = 2)]
        [object] $Procedure01,

        [Parameter(Mandatory = $false, Position = 3)]
        [object] $Procedure02,

        [Parameter(Mandatory = $false, Position = 4)]
        [object] $Procedure03,

        [Parameter(Mandatory = $false, Position = 5)]
        [object] $Procedure04,

        [Parameter(Mandatory = $false, Position = 6)]
        [object] $Procedure05,

        [Parameter(Mandatory = $false, Position = 7)]
        [object] $Procedure06,

        [Parameter(Mandatory = $false, Position = 8)]
        [object] $Procedure07,

        [Parameter(Mandatory = $false, Position = 9)]
        [object] $Procedure08,

        [Parameter(Mandatory = $false, Position = 10)]
        [object] $Procedure09,

        [Parameter(Mandatory = $false, Position = 11)]
        [object] $Procedure10,

        [Parameter(Mandatory = $false, Position = 12)]
        [object] $Procedure11
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

        # Int reference
        $_int = 1

        # Establish variable that contains the playbook update
        $_procedures = [list[pscustomobject]]::new()
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            ResponseUrl           =   $null
            Value                 =   $Id
        }

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
                $ErrorObject.ResponseUrl = "$BaseUrl/playbooks/$($Pb.id)/"
                return $ErrorObject
            }
        }


        # Retrieve Playbook's procedures
        $ExistingProcedures = Get-LrPlaybookProcedures -Name $Pb.id

        if ($ExistingProcedures.count -ge 1) {
            Write-Verbose "Procedure 1 Exists, id: $($ExistingProcedures[0].id)"
            $_procedure = [PSCustomObject]@{
                id = $ExistingProcedures[0].id
            }

            # Establish new name, otherwise keep existing name
            if ($Procedure01.Name) {
                $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure01.Name
            } else {
                $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[0].Name
            }

            # Establish new description, otherwise keep existing description
            if ($Procedure01.Description) {
                $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure01.Description
            } else {
                $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[0].Description
            }

            # Establish new due duration, otherwise keep existing due duration
            if ($Procedure01.Description) {
                $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure01.Description
            } else {
                $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[0].Description
            }
            
            # Append the updated procedure to the arraylist of PlaybookProcedures
            $_procedures.add($_procedure)
        } else {
            Write-Verbose "New Procedure 1"
            # Ensure value for duewithinSeconds provided
            if ($Procedure01.duewithinseconds) {
                $_dueWithinSeconds = $Procedure01.duewithinseconds
            } else {
                $_dueWithinSeconds = 0
            }
            Write-Host $Procedure01.name
            $_procedure = [PSCustomObject]@{
                name = $Procedure01.name
                description = $Procedure01.description
                dueWithinSeconds = $_dueWithinSeconds
            }

            Write-Verbose "Procedure: $_procedure"

            # Append the new procedure to the arraylist of PlaybookProcedures
            $_procedures.add($_procedure)

            Write-Verbose "Playbook Procedures: $PlaybookProcedures"
        }

        if ($Procedure02 -or ($ExistingProcedures.count -ge 2)) {
            if ($ExistingProcedures.count -ge 2) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[1].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure02.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure02.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[1].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure02.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure02.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[1].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure02.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure02.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[1].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure02.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure02.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure02.name
                    description = $Procedure02.description
                    dueWithinSeconds = $Procedure02.duewithinseconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }


        if ($Procedure03 -or ($ExistingProcedures.count -ge 3)) {
            if ($ExistingProcedures.count -ge 3) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[2].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure03.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure03.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[2].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure03.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure03.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[2].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure03.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure03.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[2].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure03.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure03.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure03.name
                    description = $Procedure03.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }


        if ($Procedure04 -or ($ExistingProcedures.count -ge 4)) {
            if ($ExistingProcedures.count -ge 4) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[3].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure04.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure04.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[3].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure04.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure04.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[3].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure04.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure04.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[3].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure04.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure04.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure04.name
                    description = $Procedure04.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        if ($Procedure05 -or ($ExistingProcedures.count -ge 5)) {
            if ($ExistingProcedures.count -ge 5) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[4].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure05.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure05.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[4].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure05.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure05.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[4].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure05.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure05.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[4].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure05.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure05.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure05.name
                    description = $Procedure05.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        if ($Procedure06 -or ($ExistingProcedures.count -ge 6)) {
            if ($ExistingProcedures.count -ge 6) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[5].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure06.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure06.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[5].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure06.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure06.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[5].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure06.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure06.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[5].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure06.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure06.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure06.name
                    description = $Procedure06.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        if ($Procedure07 -or ($ExistingProcedures.count -ge 7)) {
            if ($ExistingProcedures.count -ge 7) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[6].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure07.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure07.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[6].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure07.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure07.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[6].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure07.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure07.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[6].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure07.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure07.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure07.name
                    description = $Procedure07.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        if ($Procedure08 -or ($ExistingProcedures.count -ge 8)) {
            if ($ExistingProcedures.count -ge 8) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[7].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure08.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure08.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[7].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure08.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure08.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[7].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure08.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure08.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[7].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure08.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure08.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure08.name
                    description = $Procedure08.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        if ($Procedure09 -or ($ExistingProcedures.count -ge 9)) {
            if ($ExistingProcedures.count -ge 9) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[8].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure09.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure09.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[8].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure09.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure09.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[8].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure09.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure09.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[8].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure09.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure09.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure09.name
                    description = $Procedure09.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        if ($Procedure10 -or ($ExistingProcedures.count -ge 10)) {
            if ($ExistingProcedures.count -ge 10) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[9].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure10.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure10.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[9].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure10.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure10.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[9].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure10.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure10.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[9].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure10.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure10.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure10.name
                    description = $Procedure10.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        if ($Procedure11 -or ($ExistingProcedures.count -ge 11)) {
            if ($ExistingProcedures.count -ge 11) {
                $_procedure = [PSCustomObject]@{
                    id = $ExistingProcedures[10].id
                }

                # Establish new name, otherwise keep existing name
                if ($Procedure11.Name) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $Procedure11.Name
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name name -Value $ExistingProcedures[10].Name
                }

                # Establish new description, otherwise keep existing description
                if ($Procedure11.Description) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $Procedure11.Description
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name description -Value $ExistingProcedures[10].Description
                }

                # Establish new due duration, otherwise keep existing due duration
                if ($Procedure11.duewithinseconds) {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $Procedure11.duewithinseconds
                } else {
                    $_procedure | Add-Member -MemberType NoteProperty -Name dueWithinSeconds -Value $ExistingProcedures[10].Description
                }
                
                # Append the updated procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            } else {
                # Ensure value for duewithinSeconds provided
                if ($Procedure11.duewithinseconds) {
                    $_dueWithinSeconds = $Procedure11.duewithinseconds
                } else {
                    $_dueWithinSeconds = 0
                }
                $_procedure = [PSCustomObject]@{
                    name = $Procedure11.name
                    description = $Procedure11.description
                    dueWithinSeconds = $_dueWithinSeconds
                }

                # Append the new procedure to the arraylist of PlaybookProcedures
                $PlaybookProcedures.add($_procedure)
            }
        }

        $RequestUrl = $BaseUrl + "/playbooks/$($Pb.id)/procedures/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        Write-Verbose "Procedures: $_procedures"
        # Request Body
        $Body = @($_procedures)
        $BodyContents = $Body | ConvertTo-Json
        Write-Verbose "[$Me]: Body: $Body"


        # Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Code = $Err.statusCode
                $ErrorObject.Type = "WebException"
                $ErrorObject.Note = $Err
                $ErrorObject.ResponseUrl = $RequestUrl
                $ErrorObject.Error = $true
                return $ErrorObject
            }
        }

        return $Response
    }


    End { }
}