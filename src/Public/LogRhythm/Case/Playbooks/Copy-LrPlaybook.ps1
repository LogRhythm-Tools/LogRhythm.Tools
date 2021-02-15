using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Copy-LrPlaybook {
    <#
    .SYNOPSIS
        Create a clone of a playbook from LogRhythm.
    .DESCRIPTION
        Create a clone of a playbook along with its tags, attachments, and procedures.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        ID or Name of an existing Playbook.
    .PARAMETER Name
        Name of the new Playbook.
    .OUTPUTS
        PSCustomObject representing the deleted playbook.
    .EXAMPLE
        PS C:\> Copy-LrPlaybook -Id E10111E4-DDC7-4D98-A619-5B80CA55BABF -Name "Newer Playbook"
        ---

        id            : 23F49972-166C-4B9E-9232-352FF16ACE0C
        name          : Newer Playbook
        description   : Its pretty good.
        permissions   : @{read=privateOwnerOnly; write=privateOwnerOnly}
        owner         : @{number=-100; name=LogRhythm Administrator; disabled=False}
        retired       : False
        entities      : {@{number=1; name=Primary Site; fullName=Primary Site}}
        dateCreated   : 2020-06-07T12:50:58.4124223Z
        dateUpdated   : 2020-06-07T12:50:58.4124223Z
        lastUpdatedBy : @{number=-100; name=LogRhythm Administrator; disabled=False}
        tags          : {@{number=9; text=abc}}
    .EXAMPLE
        PS C:\> Copy-LrPlaybook -Id "New Playbook" -Name "Newer Playbook"
        ---

        id            : 23F49972-166C-4B9E-9232-352FF16ACE0C
        name          : Newer Playbook
        description   : Its pretty good.
        permissions   : @{read=privateOwnerOnly; write=privateOwnerOnly}
        owner         : @{number=-100; name=LogRhythm Administrator; disabled=False}
        retired       : False
        entities      : {@{number=1; name=Primary Site; fullName=Primary Site}}
        dateCreated   : 2020-06-07T12:50:58.4124223Z
        dateUpdated   : 2020-06-07T12:50:58.4124223Z
        lastUpdatedBy : @{number=-100; name=LogRhythm Administrator; disabled=False}
        tags          : {@{number=9; text=abc}}
    .NOTES
        LogRhythm-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 0
        )]
        [ValidateNotNullOrEmpty()]
        [string] $Id,


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Name,


        [Parameter(Mandatory = $false, Position = 2)]
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
        $Method = $HttpMethod.Post

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
            Value                 =   $Id
            Raw                   =   $null
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
                return $ErrorObject
            }
        }


        $RequestUrl = $BaseUrl + "/playbooks/clone/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # Request Body
        $Body = [PSCustomObject]@{
            id = $Pb.id
            name = $Name
        }
        $Body = $Body | ConvertTo-Json
        Write-Verbose "[$Me]: Body: $Body"


        # Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Code = $Err.statusCode
            $ErrorObject.Type = "WebException"
            $ErrorObject.Note = $Err
            $ErrorObject.Error = $true
            $ErrorObject.Raw = $_
            return $ErrorObject
        }

        return $Response
    }


    End { }
}