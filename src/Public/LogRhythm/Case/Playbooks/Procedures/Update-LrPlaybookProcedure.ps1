using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrProcedure {
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
            id = ProcedureStepID, 
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
        [string] $Id
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
            $Pb = Get-LrPlaybooks -Name $Id -Credential $Credential -Exact
            if (!$Pb.Name -eq $Id) {
                $ErrorObject.Code = "404"
                $ErrorObject.Error = $true
                $ErrorObject.Type = "Null"
                $ErrorObject.Note = "Playbook does not exist."
                $ErrorObject.ResponseUrl = "$BaseUrl/playbooks/$($Pb.id)/"
                return $ErrorObject
            }
        }

        if($Tags) {
            $_tags = @()
            # multiple values, create an object
            ForEach ($Tag in $Tags) {
                Write-Verbose "$(Get-TimeStamp) Processing Tag: $Tag"
                $TagResults = Get-LrTagNumber $Tag
                if (($TagResults.Error -eq $True) -or ($null -eq $TagResults)) {
                    Write-Verbose "$(Get-TimeStamp) Non-existant tag: $Tag"
                    # If force is enabled, create the tag
                    if ($Force) {
                        Write-Verbose "$(Get-TimeStamp) Force Set - Creating Tag"
                        if (!([int]::TryParse($Tag, [ref]$_int))) {
                            $NewTagResults = New-LrTag -Tag $Tag
                            if (($null -eq $NewTagResults.Error) -or ($NewTagResults.Error -eq "")) {
                                Write-Verbose "$(Get-TimeStamp) Adding new tag number: $($NewTagResults.number) to variable: _tags"
                                $_tags += $NewTagResults.number
                            }
                        } else {
                            $ErrorObject.Code = "Value"
                            $ErrorObject.Error = $true
                            $ErrorObject.Type = "Type mismatch"
                            $ErrorObject.Note = "Request tag is integer.  New tags must be type String."
                            $ErrorObject.ResponseUrl = "Reference: New-LrTag"
                            $ErrorObject.Value = $Tag
                            return $ErrorObject
                        }
                    } else {
                        $ErrorObject.Code = "Value"
                        $ErrorObject.Error = $true
                        $ErrorObject.Type = "Missing tag"
                        $ErrorObject.Note = "Request tag does not exist.  Create tag or re-run with -force."
                        $ErrorObject.ResponseUrl = "get-lrtags -name $tag -exact"
                        $ErrorObject.Value = $Tag
                        return $ErrorObject
                    }
                # Tag exists, set _tags to TagResults
                } else {
                    Write-Verbose "$(Get-TimeStamp) Adding existing tag number: $TagResults to variable: _tags"
                    $_tags += $TagResults
                }
            }
        # No tags requested, set tags to previous value.
        } else {
            $_tags = $Pb.tags.number
        }

        # New new value set, apply new value.  Otherwise keep existing value.
        if($Entities) {
            $_entities = Get-LrEntities -Name $Entities
        } else {
            $_entities = $Pb.entities.number
        }

        # New new value set, apply new value.  Otherwise keep existing value.
        if ($Description) {
            $_description = $Description
        } else {
            $_description = $Pb.description
        }

        # New new value set, apply new value.  Otherwise keep existing value.
        if ($Name) {
            $_name = $Name
        } else {
            $_name = $Pb.Name
        }

        # New new value set, apply new value.  Otherwise keep existing value.
        if ($ReadPermission) {
            $_readPermission = $ReadPermission
        } else {
            $_readPermission = $Pb.permissions.read
        }

        # New new value set, apply new value.  Otherwise keep existing value.
        if ($WritePermission) {
            $_writePermission = $WritePermission
        } else {
            $_writePermission = $Pb.permissions.write
        }

        $RequestUrl = $BaseUrl + "/playbooks/$($Pb.id)/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # Request Body
        $Body = [PSCustomObject]@{
            name = $_name
            description = $_description
            permissions = [PSCustomObject]@{
                read = $_readPermission
                write = $_writePermission
            }
            entities = @(
                $_entities
        
            )
            tags = @(
                $_tags
            )
        }
        $Body = $Body | ConvertTo-Json
        Write-Verbose "[$Me]: Body: $Body"


        # Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
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
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
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