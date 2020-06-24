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
        PSCustomObject representing the added playbook.
    .EXAMPLE
        PS C:\> 
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


        [Parameter(Mandatory = $true, Position = 2)]
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
        $Method = $HttpMethod.Delete
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

        $RequestUrl = $BaseUrl + "/cases/$CaseNumber/playbooks/$PlaybookId/"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"


        # Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                if ($Err.statusCode -eq "409") {
                    # we know we can use $Pb.name because a 409 wouldn't throw unless the playbook existed.
                    throw [InvalidOperationException] "[409]: Playbook '$($Pb.name)' has already been added to case '$Id'"
                }
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                if ($Err.statusCode -eq "409") {
                    # we know we can use $Pb.name because a 409 wouldn't throw unless the playbook existed.
                    throw [InvalidOperationException] "[409]: Playbook '$($Pb.name)' has already been added to case '$Id'"
                }
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }

        return $Response
    }


    End { }
}