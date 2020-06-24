using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrPlaybook {
    <#
    .SYNOPSIS
        Apply updates to a LogRhythm playbook.
    .DESCRIPTION
        Update an existing playbook.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Id or Name of the existing playbook.
    .PARAMETER Name
        Name of the playbook.  Updates may be applied to this field.  If absent the existing value will remain.
        
        Limited to 150 characters.
    .PARAMETER Description
        Summary of the playbook.  Updates may be applied to this field.  If absent the existing value will remain.
        
        Limited to 1000 characters.
    .PARAMETER Permissions
        Roles and entities that can read/write to this playbook.

        Updates may be applied to this field.  If absent the existing value will remain.
    .PARAMETER Entities
        List of entity numbers that can access this playbook.  An empty list will assign the playbook to the user's default entity.

        Updates may be applied to this field.  If absent the existing value will remain.
    .PARAMETER Tags
        List of tag (identifiers or names).

        Updates may be applied to this field.  If absent the existing value will remain.
    .PARAMETER Force
        The Force switch will initiate the creation of referenced Tags if they do not exist in LogRhythm and apply them to the playbook.
    .INPUTS
        [System.Object] "Id" ==> [Id] : The ID of the Case to modify.
    .OUTPUTS
        PSCustomObject representing the added playbook.
    .EXAMPLE
        PS C:\> Update-LrPlaybook -Id "This ones better 9." -Description "This description is better than the last." -Tags @("Srexob", "Rekcits") -Force

        id            : E10111E4-DDC7-4D98-A619-5B80CA55BABF
        name          : This ones better 9.
        description   : Just a bit different.
        permissions   : @{read=privateOwnerOnly; write=privateOwnerOnly}
        owner         : @{number=-100; name=LogRhythm Administrator; disabled=False}
        retired       : False
        entities      : {@{number=1; name=Primary Site; fullName=Primary Site}}
        dateCreated   : 2020-06-06T19:31:24.6916651Z
        dateUpdated   : 2020-06-06T19:31:24.6916651Z
        lastUpdatedBy : @{number=-100; name=LogRhythm Administrator; disabled=False}
        tags          : {@{number=8; text=Boxers}, @{number=7; text=Sticker}}

    .EXAMPLE
        PS C:\> Update-LrPlaybook -Id "New Playbook" -Name "New2 Playbook"

        id            : EB042520-5EEA-4CE5-9AF5-3A05EFD9BC88
        name          : New2 Playbook
        description   : Its pretty good.
        permissions   : @{read=privateOwnerOnly; write=privateOwnerOnly}
        owner         : @{number=-100; name=LogRhythm Administrator; disabled=False}
        retired       : False
        entities      : {@{number=1; name=Primary Site; fullName=Primary Site}}
        dateCreated   : 2020-06-07T12:48:45.9064572Z
        dateUpdated   : 2020-06-07T14:16:35.6891774Z
        lastUpdatedBy : @{number=-100; name=LogRhythm Administrator; disabled=False}
        tags          : {@{number=9; text=abc}}
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

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [string] $Name,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [string] $Description,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [string] $Permissions,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [string] $Entities,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [object[]] $Tags,

        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $Force
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
            catch {
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