using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Remove-LrCasePlaybook {
    <#
    .SYNOPSIS
        Remove a playbook from a LogRhythm case.
    .DESCRIPTION
        The Remove-LrCasePlaybook cmdlet removes a playbook from an existing case.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string,
        or as a number.
    .PARAMETER Playbook
        Unique identifier for the playbook. This can either be the Playbook's ID
        as an RFC 4122 formatted string, or the exact name of the playbook.
    .INPUTS
        [System.Object] "Id" ==> [Id] : The ID of the Case to modify.
    .OUTPUTS
        Successful removal of a playbook from a case returns a null.
    .EXAMPLE
        PS C:\> Remove-LrCasePlaybook -Id 2 -Playbook "Phishing"

    .EXAMPLE
        PS C:\> Remove-LrCasePlaybook -Id "Mock case" -Playbook "Phishing"

    .EXAMPLE
        PS C:\> Remove-LrCasePlaybook -Id "Mock case" -Playbook "Phishing"

        Error       : True
        Type        : 404
        Note        : Playbook GUID/Name not found on case: 2.  Review: Get-LrCasePlaybooks -Id 2
        ResponseUrl :
        Value       : Phishing
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
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNull()]
        [string] $Playbook,


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
        

        # Request URI
        $Method = $HttpMethod.Delete
    }


    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Id
            Raw                   =   $null
        }

        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }   



        # Validate Playbook Ref
        if (Test-Guid $Playbook) {
            # If $Playbook is a valid Guid format
            # Get Playbook by Guid

            $Pb = Get-LrCasePlaybooks -Id $CaseNumber
            
            # Return error if retrieval failed
            if ($Pb.error -eq $true) {
                Return $Pb
            }
            # Step through each Playbook to identify potential match by name
            ForEach ($Book in $Pb) {
                if ($Playbook -eq $Book.id) {
                    $PlaybookId = $Book.id
                }
            }
        } else {
            # If $Playbook is in string/name format
            $Pb = Get-LrCasePlaybooks -Id $CaseNumber
            
            # Return error if retrieval failed
            if ($Pb.error -eq $true) {
                Return $Pb
            }
            # Step through each Playbook to identify potential match by name
            ForEach ($Book in $Pb) {
                if ($Playbook -eq $Book.name) {
                    $PlaybookId = $Book.id
                }
            }
        }

        if ($null -eq $PlaybookId) {
            $ErrorObject.Error = $true
            $ErrorObject.Type = "404"
            $ErrorObject.Value = $Playbook
            $ErrorObject.Note = "Playbook GUID/Name not found on case: $CaseNumber.  Review: Get-LrCasePlaybooks -Id $CaseNumber"
            return $ErrorObject
        }

        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/playbooks/$PlaybookId/"
        
        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        if ($PassThru) {
            return $Response
        }
    }


    End { }
}