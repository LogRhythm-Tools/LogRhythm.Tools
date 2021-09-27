using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrIdentity {
    <#
    .SYNOPSIS
        Update an Identity to TrueIdentity.
    .DESCRIPTION
        Update-LrIdentity returns an object containing the detailed results of the updated Identity.
    .PARAMETER IdentityId
        Identity ID # for the True Identity record to be updated.  This is a required parameter.
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
    .PARAMETER AddressCity
        AddressCity string value for the TrueIdentity record.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its status.
    .EXAMPLE
        Update-LrIdentity -IdentityId 111 -Department "TAM" -Manager "Eric Hart" -Title "TrueID Service Account" -Company "LogRhythm, Inc." -AddressCity "Boulder"  -PassThru

        nameFirst         : svc
        nameMiddle        :
        nameLast          : LRIdentitySync
        displayIdentifier : svc_lridentitysync@tam.lr
        company           : LogRhythm, Inc.
        department        : TAM
        title             : TrueID Service Account
        manager           : Eric Hart
        addressCity       : Boulder
        recordStatus      : Active
    .EXAMPLE
        Update-LrIdentity -IdentityId 411 -Department "TAM" -Manager "Eric Hart" -Company "LogRhythm, Inc." -AddressCity "Boulder"  -PassThru

        Error      : True
        Note       : IdentityID 411 does not exist or you don't have access to see it
        Code       : 404
        Type       : System.Net.WebException
        IdentityId : 411
        Raw        : {"statusCode":404,"message":"IdentityID 411 does not exist or you don't have access to see it"}
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, valuefrompipelinebypropertyname = $true, Position = 0)]
        [int32] $IdentityId,


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
        [string] $AddressCity,

                
        [Parameter(Mandatory = $false, Position = 10)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 11)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Put

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Establish Object for new TrueIdentity records
        $NewIdentities = [list[object]]::new()
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            Code                  =   $null
            Type                  =   $null
            NameFirst             =   $NameFirst
            NameLast              =   $NameLast
            Raw                   =   $null
        }
        $ExistingIdentity = Get-LrIdentityById -IdentityId $IdentityId
        if ($ExistingIdentity.error -eq $true) {
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
            $Identity | Add-Member -NotePropertyName nameMiddle -NotePropertyValue $NameFirst
        } else {
            $Identity | Add-Member -NotePropertyName nameMiddle -NotePropertyValue $ExistingIdentity.nameMiddle
        }


        # NameLast - Required
        if ($NameMiddle) {
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
            $Identity | Add-Member -NotePropertyName company -NotePropertyValue $ExistingIdentity.company
        }

        if ($Department) {
            $Identity | Add-Member -NotePropertyName department -NotePropertyValue $Department
        } else {
            $Identity | Add-Member -NotePropertyName department -NotePropertyValue $ExistingIdentity.department
        }

        if ($Title) {
            $Identity | Add-Member -NotePropertyName title -NotePropertyValue $Title
        } else {
            $Identity | Add-Member -NotePropertyName title -NotePropertyValue $ExistingIdentity.title
        }

        if ($Manager) {
            $Identity | Add-Member -NotePropertyName manager -NotePropertyValue $Manager
        } else {
            $Identity | Add-Member -NotePropertyName manager -NotePropertyValue $ExistingIdentity.manager
        }

        if ($AddressCity) {
            $Identity | Add-Member -NotePropertyName addressCity -NotePropertyValue $AddressCity
        } else {
            $Identity | Add-Member -NotePropertyName addressCity -NotePropertyValue $ExistingIdentity.addressCity
        }

        if ($RecordStatus) {
            $Identity | Add-Member -NotePropertyName recordStatus -NotePropertyValue $RecordStatus
        } else {
            $Identity | Add-Member -NotePropertyName recordStatus -NotePropertyValue $ExistingIdentity.recordStatus
        }

        # Establish Body Contents
        $BodyContents = $($Identity | ConvertTo-Json -Depth 5)

        Write-Verbose $BodyContents

        # Define Query URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/identities/$IdentityId/"

        # Send Request
        try {
            $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
        } catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            $ErrorObject.Error = $true
            $ErrorObject.Type = "System.Net.WebException"
            $ErrorObject.Code = $($Err.statusCode)
            $ErrorObject.Note = $($Err.message)
            $ErrorObject.Raw = $_
            return $ErrorObject
        }


        if ($PassThru) {
            return $Response
        }

    }

    End { 
        
    }
}