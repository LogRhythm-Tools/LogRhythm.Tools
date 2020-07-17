using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrNoteToCase {
    <#
    .SYNOPSIS
        Add-LrNoteToCase
    .DESCRIPTION
        Add-LrNoteToCase
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        The Id of the case for which to add a note.
    .PARAMETER Text
        Text of note to add   
    .INPUTS
        Type -> Parameter
    .OUTPUTS
        PSCustomObject representing the (new|modified) LogRhythm object.
    .EXAMPLE
        PS C:\> Add-LrNoteToCase -Id 1780 -Text "Review of alarm 21202 indicated manual action from System Administrator." -PassThru
        ---

        number        : 4
        dateCreated   : 2020-07-17T01:49:47.0452267Z
        dateUpdated   : 2020-07-17T01:49:47.0452267Z
        createdBy     : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy : @{number=1; name=lrtools; disabled=False}
        type          : note
        status        : completed
        statusMessage :
        text          : Review of alarm 21202 indicated manual action from System Administrator.
        pinned        : False
        datePinned    :
    .EXAMPLE
        PS C:\> Add-LrNoteToCase -Id 2 -Text "This is my note for case 2!" -PassThru       
        ---

        number        : 5
        dateCreated   : 2020-07-17T01:51:45.7467156Z
        dateUpdated   : 2020-07-17T01:51:45.7467156Z
        createdBy     : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy : @{number=1; name=lrtools; disabled=False}
        type          : note
        status        : completed
        statusMessage :
        text          : This is my note for case 2!
        pinned        : False
        datePinned    :
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


        [Parameter(
            Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
        )]
        [ValidateNotNull()]
        [object] $Id,


        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $Text,

        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru
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

        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/evidence/note/"


        # Request Body
        $Body = [PSCustomObject]@{ text = $Text } | ConvertTo-Json
        Write-Verbose "[$Me] Request Body:`n$Body"

        # REQUEST
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

        # Return
        if ($PassThru) {
            return $Response    
        }        
    }


    End { }
}