using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrIdentity {
    <#
    .SYNOPSIS
        Update an Identity in TrueIdentity.  This cmdlet does not cover creating or disabling any identifiers associated with a given record.

        For managing Identifiers associated with a TrueIdentity record see Add-LrIdentityIdentifier, Enable-LrIdentityIdentifier, and Disable-LrIdentityIdentifier.
    .DESCRIPTION
        Update-LrIdentity returns an object containing the detailed results of the updated Identity when provided the PassThru switch.
    .PARAMETER IdentityId
        Identity ID # for the TrueIdentity record to be updated.
    .PARAMETER NameFirst
        First name string value for the TrueIdentity record.
    .PARAMETER NameMiddle
        Middle name string value for the TrueIdentity record.
    .PARAMETER NameLast
        Last name string value for the TrueIdentity record.
    .PARAMETER DisplayIdentifier
        DisplayIdentifier string value for the TrueIdentity record.
    .PARAMETER Department
        Department string value for the TrueIdentity record.
    .PARAMETER Manager
        Manager string value for the TrueIdentity record.
    .PARAMETER Company
        Company string value for the TrueIdentity record.
    .PARAMETER Title
        Title string value for the TrueIdentity record.
    .PARAMETER RecordStatus
        Status of the TrueIdentity Record as Active or Retired.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its status.
    .EXAMPLE
        PS C:\> Update-LrIdentity -IdentityID 8 -NameLast "Hart" -PassThru
        ---
        nameFirst         : Eric
        nameMiddle        : 
        nameLast          : Hart
        displayIdentifier : Eric.Hart
        company           : LogRhythm
        department        : Customer Success
        title             : Manager, Subscription Services
        manager           : Chuck Talley
        addressCity       : 
        recordStatus      : Active
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, valuefrompipelinebypropertyname = $true, Position = 0)]
        [int] $IdentityId,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 1)]
        [string] $NameFirst,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 2)]
        [string] $NameMiddle,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 3)]
        [string] $NameLast,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 4)]
        [string] $DisplayIdentifier,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 5)]
        [string] $Department,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 6)]
        [string] $Manager,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 7)]
        [string] $Company,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 8)]
        [string] $Title,


        [Parameter(Mandatory = $false, valuefrompipelinebypropertyname = $true, Position = 9)]
        [string] $RecordStatus,


        [Parameter(Mandatory = $false, Position = 10)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 11)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        

        # Define HTTP Method
        $Method = $HttpMethod.Put

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Lookup Existing TrueIdentity Record for Update
        $ExistingIdentity = Get-LrIdentityById -IdentityId $IdentityId
        if ($ExistingIdentity.Error) {
            return $ExistingIdentity
        }

         # Section - Build JSON Body - Begin
        $Identity = [PSCustomObject]@{}

        # NameFirst - Required
        if ($NameFirst) {
            $Identity | Add-Member -NotePropertyName nameFirst -NotePropertyValue $NameFirst
        } else {
            $Identity | Add-Member -NotePropertyName nameFirst -NotePropertyValue $ExistingIdentity.nameFirst
        }
        
        # NameMiddle - Optional
        if ($NameMiddle) {
            $Identity | Add-Member -NotePropertyName nameMiddle -NotePropertyValue $NameMiddle
        } else {
            if ($ExistingIdentity.nameMiddle) {
                $Identity | Add-Member -NotePropertyName nameMiddle -NotePropertyValue $ExistingIdentity.nameMiddle
            }
        }

        # NameLast - Required
        if ($NameLast) {
            $Identity | Add-Member -NotePropertyName nameLast -NotePropertyValue $NameLast
        } else {
            $Identity | Add-Member -NotePropertyName nameLast -NotePropertyValue $ExistingIdentity.nameLast
        }

        # DisplayIdentifier - Required
        if ($DisplayIdentifier) {
            $Identity | Add-Member -NotePropertyName displayIdentifier -NotePropertyValue $DisplayIdentifier
        } else {
            $Identity | Add-Member -NotePropertyName displayIdentifier -NotePropertyValue $ExistingIdentity.displayIdentifier
        }


        # Company, Department, Title, Manager, AddressCity, DomainNAme - Optional
        if ($Company) {
            $Identity | Add-Member -NotePropertyName company -NotePropertyValue $Company
        } else {
            if ($ExistingIdentity.company) {
                $Identity | Add-Member -NotePropertyName company -NotePropertyValue $ExistingIdentity.company
            }
        }

        if ($Department) {
            $Identity | Add-Member -NotePropertyName department -NotePropertyValue $Department
        } else {
            if ($ExistingIdentity.department) {
                $Identity | Add-Member -NotePropertyName department -NotePropertyValue $ExistingIdentity.department
            }
        }

        if ($Title) {
            $Identity | Add-Member -NotePropertyName title -NotePropertyValue $Title
        } else {
            if ($ExistingIdentity.title) {
                $Identity | Add-Member -NotePropertyName title -NotePropertyValue $ExistingIdentity.title
            }
        }

        if ($Manager) {
            $Identity | Add-Member -NotePropertyName manager -NotePropertyValue $Manager
        } else {
            if ($ExistingIdentity.manager) {
                $Identity | Add-Member -NotePropertyName manager -NotePropertyValue $ExistingIdentity.manager
            }
        }

        if ($AddressCity) {
            $Identity | Add-Member -NotePropertyName addressCity -NotePropertyValue $AddressCity
        } else {
            if ($ExistingIdentity.addressCity) {
                $Identity | Add-Member -NotePropertyName addressCity -NotePropertyValue $ExistingIdentity.addressCity
            }
        }

        if ($DomainName) {
            $Identity | Add-Member -NotePropertyName domainName -NotePropertyValue $DomainName
        } else {
            if ($ExistingIdentity.domainName) {
                $Identity | Add-Member -NotePropertyName domainName -NotePropertyValue $ExistingIdentity.domainName
            }
        }

        # RecordStatus - Required
        if ($RecordStatus) {
            $Identity | Add-Member -NotePropertyName recordStatus -NotePropertyValue $RecordStatus
        } else {
            $Identity | Add-Member -NotePropertyName recordStatus -NotePropertyValue $ExistingIdentity.recordStatus
        }

        # Establish Body Contents
        $Body = $Identity | ConvertTo-Json -Compress
        
        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/identities/" + $IdentityId

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }


        if ($PassThru) {
            return $Response
        }
    }

    End { 
    }
}