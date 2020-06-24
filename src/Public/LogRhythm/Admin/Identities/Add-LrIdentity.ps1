using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrIdentity {
    <#
    .SYNOPSIS
        Add an Identity to TrueIdentity.
    .DESCRIPTION
        Add-LrIdentity returns an object containing the detailed results of the added Identity.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER EntityId
        Entity ID # for associating new TrueIdentity Identity record.
    .PARAMETER SyncName
        Friendly name associated with the TrueIdentity record add.  Must be unique for each API call of this cmdlet.

        If no SyncName is provided a unique key will be genearted.  Key format: LRT-{10*AlphaCharacters}
    .PARAMETER Attributes

    .PARAMETER Identifiers

    .PARAMETER DryRun
        Switch that will execute a dry-run of the Add-LRIdentity function.
    .OUTPUTS
        PSCustomObject representing LogRhythm TrueIdentity Identity and its status.
    .EXAMPLE
        PS C:\> Add-LrIdentity -EntityId 1 -NameFirst Eric -NameLast Hart -DisplayIdentifier Eric.Hart -Department "Customer Success" -Company "LogRhythm Inc." -Identifier1Value "eric.hart@logrhythm.com" -Identifier1Type "both"
        ----
        vendorUniqueKey                          identityID identifierSourceAccountID
        ---------------                          ---------- -------------------------
        24638670afc7cd4e75fb8e107b223cd0680f6bae          7                         0

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

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 1)]
        [int]$EntityId,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 2)]
        [String]$SyncName,

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 3)]
        [String]$NameFirst,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 4)]
        [String]$NameMiddle,

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 5)]
        [String]$NameLast,

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 6)]
        [String]$DisplayIdentifier,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 7)]
        [String]$Department,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 8)]
        [String]$Manager,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 9)]
        [String]$Company,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 10)]
        [Byte]$PhotoThumbnail,

        [Parameter(Mandatory = $true, ValueFromPipeline=$false, Position = 11)]
        [String]$Identifier1Value,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 12)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [String]$Identifier1Type = "both",
        
        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 13)]
        [String]$Identifier2Value,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 14)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [String]$Identifier2Type = "both",


        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 15)]
        [String]$Identifier3Value,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 16)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [String]$Identifier3Type = "both",


        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 17)]
        [String]$Identifier4Value,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 18)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [String]$Identifier4Type = "both",

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 19)]
        [String]$Identifier5Value,

        [Parameter(Mandatory = $false, ValueFromPipeline=$false, Position = 20)]
        [ValidateSet('both','login', 'email', ignorecase=$true)]
        [String]$Identifier5Type = "both"
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



        # Send Request
        if ($PSEdition -eq 'Core'){
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents -SkipCertificateCheck
            }
            catch {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $ExceptionMessage
            }
        } else {
            try {
                $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $BodyContents
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