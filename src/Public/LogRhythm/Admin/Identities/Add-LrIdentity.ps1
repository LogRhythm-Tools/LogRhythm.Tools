using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrIdentity {
    <#
    .SYNOPSIS
        Add an Identity to TrueIdentity.
    .DESCRIPTION
        Add-LrIdentity returns an object containing the detailed results of the added Identity.
    .PARAMETER EntityId
        Entity ID # for associating new TrueIdentity Identity record.
    .PARAMETER SyncName
        Friendly name associated with the TrueIdentity record add.  Must be unique for each API call of this cmdlet.

        If no SyncName is provided a unique key will be genearted.  Key format: LRT-{10*AlphaCharacters}
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
    .PARAMETER PhotoThumbnail
        Currently not supported.
    .PARAMETER Identifier1Value
        Identifier 1's value represented as a string.
    .PARAMETER Identifier1Type
        Identifier 1's type.  

        Valid types: email, login, both
    .PARAMETER Identifier2Value
        Identifier 2's value represented as a string.
    .PARAMETER Identifier2Type
        Identifier 2's type.  

        Valid types: email, login, both
    .PARAMETER Identifier3Value
        Identifier 3's value represented as a string.
    .PARAMETER Identifier3Type
        Identifier 3's type.  

        Valid types: email, login, both
    .PARAMETER Identifier4Value
        Identifier 4's value represented as a string.
    .PARAMETER Identifier4Type
        Identifier 4's type.  

        Valid types: email, login, both
    .PARAMETER Identifier5Value
        Identifier 5's value represented as a string.
    .PARAMETER Identifier5Type
        Identifier 5's type.  

        Valid types: email, login, both
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its status.
    .EXAMPLE
        PS C:\> Add-LrIdentity -EntityId 1 -NameFirst Eric -NameLast Hart -DisplayIdentifier Eric.Hart -Department "Customer Success" -Company "LogRhythm Inc." -Identifier1Value "eric.hart@logrhythm.com" -Identifier1Type "both" -PassThru
        ---
        vendorUniqueKey                          identityID identifierSourceAccountID
        ---------------                          ---------- -------------------------
        24638670afc7cd4e75fb8e107b223cd0680f6bae          7                         0
    .EXAMPLE
        PS C:\> Add-LrIdentity -EntityId 1 -NameFirst Jody -NameLast Hart -DisplayIdentifier Jody.Hart -Department "Success Customer" -Company "LogRhythm Inc." -Identifier1Value "jody.hart@mhtyhrgol.com" -Identifier1Type "both"

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 0)]
        [int] $EntityId,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 1)]
        [string] $SyncName,


        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 2)]
        [string] $NameFirst,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 3)]
        [string] $NameMiddle,


        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 4)]
        [string] $NameLast,


        [Parameter(Mandatory = $true, ValueFromPipeline = $false, Position = 5)]
        [string] $DisplayIdentifier,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 6)]
        [string] $Department,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 7)]
        [string] $Manager,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 8)]
        [string] $Company,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 9)]
        [Byte] $PhotoThumbnail,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 10)]
        [string] $Identifier1Value,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 11)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [string] $Identifier1Type = "both",
        

        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 12)]
        [string] $Identifier2Value,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 13)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [string] $Identifier2Type = "both",


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 14)]
        [string] $Identifier3Value,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 15)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [string] $Identifier3Type = "both",


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 16)]
        [string] $Identifier4Value,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 17)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [string] $Identifier4Type = "both",


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 18)]
        [string] $Identifier5Value,


        [Parameter(Mandatory = $false, ValueFromPipeline = $false, Position = 19)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [string] $Identifier5Type = "both",

                
        [Parameter(Mandatory = $false, Position = 20)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 21)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.LogRhythm.ApiKey
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # If a SyncName has not been provided, establish a unique SyncName for this execution.
        if (!$SyncName) {
            $SyncName = "LRT-"+(-join (((65..90)+(97..122)) | Get-Random -Count 10 | ForEach-Object {[char]$_}))
        }


        # Create vendorUniqueKey based on SyncName
        $StringBuilder = New-Object System.Text.StringBuilder
        [System.Security.Cryptography.HashAlgorithm]::Create("SHA1").ComputeHash([System.Text.Encoding]::UTF8.GetBytes($SyncName)) | ForEach-Object {
            [Void]$StringBuilder.Append($_.ToString("x2"))
        }
        $VendorUniqueKey = $StringBuilder.ToString()

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            Code                  =   $null
            Type                  =   $null
            NameFirst             =   $NameFirst
            NameLast              =   $NameFirst
        }

         # Section - Build JSON Body - Begin
        $Accounts = [PSCustomObject]@{}
        # Photo Thumbnail - Optional - Add in ContentType validation
        if ($PhotoThumbnail) {$Accounts | Add-Member -NotePropertyName thumbnailPhoto -NotePropertyValue $PhotoThumbnail}
        # VendorUniqueKey - Required
        $Accounts | Add-Member -NotePropertyName vendorUniqueKey -NotePropertyValue $VendorUniqueKey

        <#  This section requires some testingto identify value/impact
        $Accounts | Add-Member -NotePropertyName hasOwnerIdentity -NotePropertyValue $true
        $Accounts | Add-Member -NotePropertyName hasSameRootEntityAsTarget -NotePropertyValue $true
        $Accounts | Add-Member -NotePropertyName isPrimary -NotePropertyValue $true
        
        if ($AccountType) {
            $Accounts | Add-Member -NotePropertyName accountType -NotePropertyValue "Custom"
        } else {
            $Accounts | Add-Member -NotePropertyName accountType -NotePropertyValue "AD"
        }
        #>

        # NameFirst - Required
        $Accounts | Add-Member -NotePropertyName nameFirst -NotePropertyValue $NameFirst
        # NameMiddle - Optional
        if ($NameMiddle) {$Accounts | Add-Member -NotePropertyName nameMiddle -NotePropertyValue $NameMiddle}
        # NameLast - Required
        $Accounts | Add-Member -NotePropertyName nameLast -NotePropertyValue $NameLast
        # DisplayIdentifier - Required
        $Accounts | Add-Member -NotePropertyName displayIdentifier -NotePropertyValue $DisplayIdentifier
        # Company, Department, Title, Manager, AddressCity, DomainNAme - Optional
        if ($Company) {$Accounts | Add-Member -NotePropertyName company -NotePropertyValue $Company}
        if ($Department) {$Accounts | Add-Member -NotePropertyName department -NotePropertyValue $Department}
        if ($Title) {$Accounts | Add-Member -NotePropertyName title -NotePropertyValue $Title}
        if ($Manager) {$Accounts | Add-Member -NotePropertyName manager -NotePropertyValue $Manager}
        if ($AddressCity) {$Accounts | Add-Member -NotePropertyName addressCity -NotePropertyValue $AddressCity}
        if ($DomainName) {$Accounts | Add-Member -NotePropertyName domainName -NotePropertyValue $DomainName}

        # Build out Identifiers
        # Logic - If not Email set to Login.  If not Login set to Email.  Any entry, including Both, sets both identifiers. 
        # Add validation for Login/Email/Both input and accept case insensitive.
        $Identifiers = @()
        if ($Identifier1Value) {
            if ($Identifier1Type -ne "Email") {
                $Identifiers += @{
                    identifierType = "Login"
                    value = $Identifier1Value
                } 
            }
            if ($Identifier1Type -ne "Login") {
                $Identifiers += @{
                    identifierType = "Email"
                    value = $Identifier1Value
                } 
            }
        }
        if ($Identifier2Value) {
            if ($Identifier2Type -ne "Email") {
                $Identifiers += @{
                    identifierType = "Login"
                    value = $Identifier2Value
                } 
            }
            if ($Identifier2Type -ne "Login") {
                $Identifiers += @{
                    identifierType = "Email"
                    value = $Identifier2Value
                } 
            }
        }
        if ($Identifier3Value) {
            if ($Identifier3Type -ne "Email") {
                $Identifiers += @{
                    identifierType = "Login"
                    value = $Identifier3Value
                } 
            }
            if ($Identifier3Type -ne "Login") {
                $Identifiers += @{
                    identifierType = "Email"
                    value = $Identifier3Value
                } 
            }
        }
        if ($Identifier4Value) {
            if ($Identifier4Type -ne "Email") {
                $Identifiers += @{
                    identifierType = "Login"
                    value = $Identifier4Value
                } 
            }
            if ($Identifier4Type -ne "Login") {
                $Identifiers += @{
                    identifierType = "Email"
                    value = $Identifier4Value
                } 
            }
        }
        if ($Identifier5Value) {
            if ($Identifier5Type -ne "Email") {
                $Identifiers += @{
                    identifierType = "Login"
                    value = $Identifier2Value
                } 
            }
            if ($Identifier5Type -ne "Login") {
                $Identifiers += @{
                    identifierType = "Email"
                    value = $Identifier5Value
                } 
            }
        }

        # Add identifiers to PSCustom Object
        if ($Identifiers) {
            $Accounts | Add-Member -NotePropertyName identifiers -NotePropertyValue $Identifiers
        }
        # Section - Build JSON Body - End


        # Establish Body Contents
        $BodyContents = [PSCustomObject]@{
            friendlyName = $SyncName
            accounts = @(
                $Accounts
            )
        } | ConvertTo-Json -Depth 5
        
        Write-Verbose $BodyContents

        # Define Query URL
        $RequestUrl = $BaseUrl + "/identities/bulk/?entityID=" + $EntityId


        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Note                  =   $null
            IdentityId            =   $null
            IdentifierId          =   $null
            RecordStatus          =   $null
            $IdentifierStatus     =   $null
            NameFirst             =   $null
            NameLast              =   $null
        }

        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
            }
            catch [System.Net.WebException] {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
        }

        if ($PassThru) {
            return $Response
        }
    }

    End { }
}