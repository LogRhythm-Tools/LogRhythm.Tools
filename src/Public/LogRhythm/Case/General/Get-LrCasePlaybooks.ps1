using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrCasePlaybooks {
    <#
    .SYNOPSIS
        Return a list of playbooks attached to a case.
    .DESCRIPTION
        The Get-LrCasePlaybooks cmdlet returns an object containing all the playbooks
        that has been assigned to a specific case.

        If a match is not found, this cmdlet will return null.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $SrfPreferences.LrDeployment.LrApiToken
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .INPUTS
        [System.Object]   ->  Id
    .OUTPUTS
        System.Object representing the returned LogRhythm playbooks on the applicable case.

        If a match is not found, this cmdlet will throw exception
        [System.Collections.Generic.KeyNotFoundException]
    .EXAMPLE
        PS C:\> Get-LrCasePlaybooks -Id 8703
        ---
        id                 : E560822B-3685-48DE-AC25-0314B1C4124F
        name               : Phishing
        description        : Use this Playbook when someone has received a malicious phishing email that contains malicious code, a link to malicious code, or is employing social engineering to
                            obtain user credentials.

        originalPlaybookId : 510C7D5B-F058-4748-A948-233FAECB8348
        dateAdded          : 2019-12-23T13:31:26.0410191Z
        dateUpdated        : 2019-12-23T13:37:08.0763176Z
        lastUpdatedBy      : @{number=227; name=Domo, Derby; disabled=False}
        pinned             : False
        datePinned         :
        procedures         : @{total=7; notCompleted=7; completed=0; skipped=0; pastDue=0}

        id                 : 4CAB940D-CFF7-442E-A54A-5D4949FA783D
        name               : Compromised Account
        description        : This playbook assists analysts in handling expected cases of a compromised account.
        originalPlaybookId : 5CD58351-503E-41E4-B36C-F9C29BDD1508
        dateAdded          : 2019-12-23T13:36:04.3544575Z
        dateUpdated        : 2019-12-23T13:37:12.0184697Z
        lastUpdatedBy      : @{number=227; name=Domo, Derby; disabled=False}
        pinned             : False
        datePinned         :
        procedures         : @{total=6; notCompleted=6; completed=0; skipped=0; pastDue=0}

    .Example
        Get-LrCasePlaybooks -Id "Case 2"

        id                 : 409D10D8-0C79-4D44-B999-CC2F6358B254
        name               : New Playbook
        description        : Its pretty good.
        originalPlaybookId : EB042520-5EEA-4CE5-9AF5-3A05EFD9BC88
        dateAdded          : 2020-06-07T13:30:04.0997958Z
        dateUpdated        : 2020-06-07T13:30:04.0997958Z
        lastUpdatedBy      : @{number=-100; name=LogRhythm Administrator; disabled=False}
        pinned             : False
        datePinned         :
        procedures         : @{total=0; notCompleted=0; completed=0; skipped=0; pastDue=0}
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

        
        [Parameter(Mandatory = $false, Position = 1)]
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
        $Method = $HttpMethod.Get
    }


    Process {
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }   

        
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/playbooks/"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # REQUEST
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Return all responses.
        return $Response
    }


    End { }
}