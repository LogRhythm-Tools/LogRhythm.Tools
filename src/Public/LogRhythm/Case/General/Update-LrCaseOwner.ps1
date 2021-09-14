using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrCaseOwner {
    <#
    .SYNOPSIS
        Update the owner of a case. The new owner must already be a collaborator on the case.
    .DESCRIPTION
        xxxx
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as
        a number.
    .INPUTS
        xxxx
    .OUTPUTS
        xxxx
    .EXAMPLE
        xxxx
    .EXAMPLE
        xxxx
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
        [ValidateNotNullOrEmpty()]
        [string] $Name,

        
        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $Force,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 4)]
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
            Case                  =   $Id
            Raw                   =   $null
        } 
        
        #region: Validate Parameters                                                               
        # Test CaseId Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }


        # Validate Name + Is Collaborator
        $UserNumber = 0
        $NameInfo = Test-LrUserIdFormat -Id $Name
        if ($NameInfo.IsValid) {
            # User by Name
            if ($NameInfo.IsName) {
                $User = Get-LrUserNumber -User $NameInfo.Value
                if ($User) {
                    $UserNumber = $User
                } else {
                    throw [ArgumentException] "Unable to find a user with name $Name."
                }
            }
            # User by Number
            if ($NameInfo.IsInt) {
                $UserNumber = $NameInfo.Value
            }

            # Make sure user is a collaborator on case
            $CaseResults = Get-LrCaseById -Id $Id
            if ($CaseResults -and $CaseResults.Error -ne $true) {
                $CaseCollaborators = $CaseResults | Select-Object -ExpandProperty 'collaborators'
                if (!($CaseCollaborators.number -contains $UserNumber)) {
                    if ($Force) {
                        $AddCollabResults = Add-LrCaseCollaborators -Id $Id -Numbers $UserNumber -PassThru
                        Start-Sleep $global:APISleep
                        if ($AddCollabResults.Error -eq $true) {
                            return $AddCollabResults
                        }
                    } else {
                        $ErrorObject.Code = -1
                        $ErrorObject.Type = "Input Validation"
                        $ErrorObject.Note = "New case owner is not an existing case collaborator.  Manually add the target user to the case as a collaborator or re-run this cmdlet with the -Force flag."
                        $ErrorObject.Error = $true
                        $ErrorObject.Raw = $null
                        return $ErrorObject
                    }
                }
            } elseif ($CaseResults.Error) {
                return $CaseResults
            }

            $CaseCollaborators = Get-LrCaseById -Id $CaseNumber | Select-Object -ExpandProperty collaborators
            if ($CaseCollaborators) {
                if (!$CaseCollaborators.number -contains $UserNumber) {
                    throw [ArgumentException] "Parameter [Name:$Name] is not a collaborator on case $CaseNumber"
                }
            }
        } else {
            throw [ArgumentException] "Unable to find an active LogRhythm ID for $Name."
        }

        if (! $UserNumber) {
            throw [ArgumentException] "Unable to find an active LogRhythm ID for $Name."
        }
        #endregion
        


        #region: Send Request                                                                      
        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/actions/changeOwner/"

        # Request Body
        $Body = [PSCustomObject]@{ number = $UserNumber } | ConvertTo-Json
        
        Write-Verbose "[$Me]: request body is:`n$Body"
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

        #endregion


        # Return
        if ($PassThru) {
            return $Response
        }
    }


    End { }
}