using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrCaseStatus {
    <#
    .SYNOPSIS
        Update the status of a case.
    .DESCRIPTION
        The Update-LrCaseStatus cmdlet updates an existing case's status based on an integer
        representing one of LogRhythm's 5 status codes.

        Case Status must be changed in a particular order.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.LogRhythm.ApiKey
        with a valid Api Token.
    .PARAMETER Id
        Unique identifier for the case, either as an RFC 4122 formatted string, or as a number.
    .PARAMETER StatusNumber
        Numeric identifier of the Case's Status. Status must be an integer between 1 and 5.
        1 - [Case]      Created
        2 - [Case]      Completed
        3 - [Incident]  Open
        4 - [Incident]  Mitigated
        5 - [Incident]  Resolved
    .PARAMETER Force
        Will cause the cmdlet to take into consideration the current case status and apply
        any required status transitions to achieve the target status.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .INPUTS
        [System.Object]   ->  Id
        [System.Int32]    ->  StatusNumber
    .OUTPUTS
        PSCustomObject representing the modified LogRhythm Case.
    .EXAMPLE
        PS C:\> Update-LrCaseStatus -id 2 -Status 2 -Force
    .EXAMPLE
        PS C:\> Update-LrCaseStatus -id "case 2" -Status 1 -Summary
        ---
        Updated 1 cases to status 1
    .EXAMPLE
        PS C:\> Update-LrCaseStatus -id "case 2" -Status 1 -PassThru
        ---
        id                      : 408C2E88-2E5D-4DA5-90FE-9F4D63B5B709
        number                  : 2
        externalId              :
        dateCreated             : 2020-06-06T13:46:49.4964154Z
        dateUpdated             : 2020-07-17T02:03:20.2314328Z
        dateClosed              :
        owner                   : @{number=1; name=lrtools; disabled=False}
        lastUpdatedBy           : @{number=1; name=lrtools; disabled=False}
        name                    : Case 2
        status                  : @{name=Created; number=1}
        priority                : 5
        dueDate                 : 2020-06-07T13:46:44Z
        resolution              : 
        resolutionDateUpdated   :
        resolutionLastUpdatedBy :
        summary                 :
        entity                  : @{number=-100; name=Global Entity; fullName=Global Entity}
        collaborators           : {@{number=-100; name=LogRhythm Administrator; disabled=False}, @{number=1; name=lrtools; disabled=False}}
        tags                    : {}
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
        [ValidateSet('Created', 'Completed', 'Incident', 'Mitigated', 'Resolved', ignorecase=$true)]
        [string] $Status,


        [Parameter(Mandatory = $false, Position = 2)]
        [switch] $Force,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $Summary,


        [Parameter(Mandatory = $false, Position = 5)]
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
        $Method = $HttpMethod.Put

        # Set initial ProcessedCount
        $ProcessedCount = 0
    }


    Process {
        # Test CaseID Format
        $IdStatus = Test-LrCaseIdFormat $Id
        if ($IdStatus.IsValid -eq $true) {
            $CaseNumber = $IdStatus.CaseNumber
        } else {
            return $IdStatus
        }

        # Validate Case Status
        $_status = ConvertTo-LrCaseStatusId -Status $Status
        if ($_status.Error) {
            return $_status
        }
        # Request URI
        $RequestUrl = $BaseUrl + "/lr-case-api/cases/$CaseNumber/actions/changeStatus/"

        if ($Force) {
            $CurrentCase = Get-LrCaseById -Id $CaseNumber
            Switch ($CurrentCase.status.number) {
                1 {
                    Switch ($_status) {
                        4 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        5 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                            $Body = [PSCustomObject]@{
                                statusNumber = 4
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        default {
                            continue
                        }
                    }
                }
                2 {
                    Switch ($_status) {
                        3 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 1
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        4 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 1
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        5 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 1
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }

                            $Body = [PSCustomObject]@{
                                statusNumber = 4
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        default {
                            continue
                        }
                    }
                }
                3 {
                    Switch ($_status) {
                        2 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 1
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        5 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 4
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        default {
                            continue
                        }
                    }
                }
                4 {
                    Switch ($_status) {
                        1 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        2 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                            $Body = [PSCustomObject]@{
                                statusNumber = 1
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        default {
                            continue
                        }
                    }
                }
                5 {
                    Switch ($_status) {
                        1 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 4
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        2 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 4
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                            $Body = [PSCustomObject]@{
                                statusNumber = 3
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                            $Body = [PSCustomObject]@{
                                statusNumber = 1
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        3 {
                            $Body = [PSCustomObject]@{
                                statusNumber = 4
                            } | ConvertTo-Json
                            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                            if ($Response.Error) {
                                return $Response
                            }
                        }
                        default {
                            continue
                        }
                    }
                }
            }
        }

        # Request Body
        $Body = [PSCustomObject]@{
            statusNumber = $_status
        } | ConvertTo-Json

        # Send Request
        Write-Verbose "[$Me]: request body is:`n$Body"


        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if ($Response.Error) {
            return $Response
        }

        $ProcessedCount++

        # Return
        if ($PassThru) {
            return $Response    
        }
    }

    
    End { 
        if ($Summary) {
            Write-Host "Updated $ProcessedCount cases to status $Status"
        }
    }
}