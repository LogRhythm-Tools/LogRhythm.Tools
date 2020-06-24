using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrCasePlaybook {
    <#
    .SYNOPSIS
        Add a playbook to a LogRhythm case.
    .DESCRIPTION
        The Add-LrCasePlaybook cmdlet adds a playbook to an existing case.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string,
        or as a number, or the exact name of the case.
    .PARAMETER Playbook
        Unique identifier for the playbook. This can either be the Playbook's ID
        as an RFC 4122 formatted string, or the exact name of the playbook.
    .INPUTS
        [System.Object] "Id" ==> [Id] : The ID of the Case to modify.
    .OUTPUTS
        PSCustomObject representing the added playbook.
    .EXAMPLE
        PS C:\> Add-LrCasePlaybook -Id "Case 2" -Playbook "New playbook"


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
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey,


        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [object] $Id,


        [Parameter( Mandatory = $true, Position = 2)]
        [ValidateNotNull()]
        [string] $Playbook
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
    }


    Process {
        # Get Case Id
        # Test CaseID Format
        $IdFormat = Test-LrCaseIdFormat $Id
        if ($IdFormat.IsGuid -eq $True) {
            # Lookup case by GUID
            try {
                $Case = Get-LrCaseById -Id $Id
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
            # Set CaseNum
            $CaseNumber = $Case.number
        } elseif(($IdFormat.IsGuid -eq $False) -and ($IdFormat.ISValid -eq $true)) {
            # Lookup case by Number
            try {
                $Case = Get-LrCaseById -Id $Id
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
            # Set CaseNum
            $CaseNumber = $Case.number
        } else {
            # Lookup case by Name
            try {
                $Case = Get-LrCases -Name $Id -Exact
            } catch {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
            # Set CaseNum
            $CaseNumber = $Case.number
        }


        # Validate Playbook Ref
        if (Test-Guid $Playbook) {
            # If $Playbook is a valid Guid format
            # Get Playbook by Guid
            $Pb = Get-LrPlaybookById -Id $Playbook
            Write-Verbose "[$Me]: Playbook: $Pb"
            if ($Pb.error -eq $true) {
                Return $Pb
            }
        } else {
            # Get Playbook by Name (Exact)
            $Pb = Get-LrPlaybooks -Name $Playbook -Exact
            if ($Pb.error -eq $true) {
                Return $Pb
            } 
        }

        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/playbooks/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        # Request Body
        $Body = [PSCustomObject]@{
            id = $Pb.id
        }
        $Body = $Body | ConvertTo-Json
        Write-Verbose "[$Me]: Body: $Body"


        # Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
            }
            catch {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $ExceptionMessage
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body
            }
            catch [System.Net.WebException] {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $ExceptionMessage
            }
        }

        return $Response
    }


    End { }
}