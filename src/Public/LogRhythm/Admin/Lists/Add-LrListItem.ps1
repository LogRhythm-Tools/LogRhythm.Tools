using namespace System
using namespace System.IO
using namespace System.Net
using namespace System.Collections.Generic

Function Add-LrListItem {
    <#
    .SYNOPSIS
        Add the provided value to the specified list from LogRhythm.
    .DESCRIPTION
        Add-LrListItem adds the supplied object to the specified list.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Identity
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER Value
        The value to be added to the specified LogRhythm List Identity.
    .PARAMETER ItemType
        For use with Lists that support multiple item types.  Add-LrListItem will attempt to auto-define
        this value.  This parameter enables setting the ItemType.
    .PARAMETER LoadListItems
        LoadListItems adds the Items property to the return of the PSCustomObject representing the 
        specified LogRhythm List when an item is successfully added.
    .INPUTS
        [System.Object] -> Name
        [System.String[array]] -> Value     The Value parameter can be provided via the PowerShell pipeline.  This value can be an array of values.
        [System.String] -> ItemType
        [System.Switch] -> LoadListItems
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List.

        If a Value parameter error is identified, a PSCustomObject is returned providing details
        associated to the error.
    .EXAMPLE
        PS C:\> Add-LrListItem -Name srfIP -Value 192.168.5.20
        ----
        listType         : IP
        status           : Active
        name             : srfIP
        useContext       : {None}
        autoImportOption : @{enabled=False; usePatterns=False; replaceExisting=False}
        id               : 2095
        guid             : 81059751-823E-4F5B-87BE-FEFFF1708E5E
        dateCreated      : 2019-12-31T03:27:30.077Z
        dateUpdated      : 2019-12-31T17:32:40.38Z
        revisitDate      : 2029-12-31T10:32:40.38Z
        readAccess       : Private
        writeAccess      : Private
        restrictedRead   : False
        entityName       : Primary Site
        entryCount       : 7
        needToNotify     : False
        doesExpire       : False
        owner            : 206
        listItemsCount   : 0

        PS C:\> Add-LrListItem -Name srfIP -Value 192.168.5.1
        ----
        Error            : True
        Value            : 192.168.5.1
        Duplicate        : True
        TypeMismatch     : False
        QuantityMismatch :
        Note             : Duplicate Value.  Value: 192.168.5.1
        ListGuid         : 81059751-823E-4F5B-87BE-FEFFF1708E5E
        ListName         : srfIP
        FieldType        : IP
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

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNull()]
        [object] $Name,

        [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=2)]
        [string[]] $Value,

        [Parameter(Mandatory=$false, Position=3)]
        [string] $ItemType,

        [Parameter(Mandatory=$false, Position=4)]
        [switch] $LoadListItems
    )
                                                                   
    Begin {
        # Request Setup
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")
        $Headers.Add("Content-Type","application/json")
        if ($LoadListItems) {
            $Headers.Add("loadListItems",$LoadListItems)
        }

        #$ExpDate = (Get-Date).AddDays(7).ToString("yyyy-MM-dd")

        # Define HTTP Method
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $Value
            Duplicate             =   $false
            TypeMismatch          =   $false
            QuantityMismatch      =   $null
            Note                  =   $null
            ListGuid              =   $null
            ListName              =   $null
            FieldType             =   $null
        }

        # Process Identity Object
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
            $Guid = $Name.ToString()
            $ErrorObject.ListName = (Get-LrList -Name $Guid | Select-Object -ExpandProperty Name)
            $ErrorObject.ListGuid = $Guid
        } else {
            $Guid = Get-LRListGuidByName -Name $Name.ToString() -Exact
            if ($Guid -is [array]) {
                throw [Exception] "Get-LrListGuidbyName returned an array of GUID.  Provide specific List Name."
            } else {
                $LrListDetails = Get-LrList -Name $Guid
                $LrListType = $LrListDetails.ListType
                $ErrorObject.ListName = $Name.ToString()
                $ErrorObject.ListGuid = $Guid
            }
        }

        # Map listItemDataType
        switch ($LrListType) {
            Application {
                if ($Value -is [array]) {
                    ForEach ($Entry in $Value) {
                        if ($Entry -like "*,*" -Or $ItemType.tolower() -eq "portrange") {
                            # Pair of Integer for TCP/UDP Port
                            if ($Entry.split(",").Count -ne 2) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "PortRange"
                                $ErrorObject.QuantityMismatch =   $true
                                $ErrorObject.Note = "Quantity Mismatch.  Values Submited: $($Entry.split(",").Count) - ValuesRequired: 2"
                            }
                            $Entry.split(",").Trim() | ForEach-Object {
                                # Validate each port
                                $PortValid = Test-ValidTCPUDPPort $_
                                if ($PortValid.IsValid -eq $false) {
                                    $ErrorObject.Error = $true
                                    $ErrorObject.FieldType =  "PortRange"
                                    $ErrorObject.Note = "Improper PortRange Value. Value Submited: $_ - ValueRange: 0-65535"
                                }
                            }
                            # Set List metadata type
                            $ListItemDataType = "PortRange"
                            $ListItemType = "PortRange"
                        } else {
                            # Validate TCP/UDP Port
                            $PortValid = Test-ValidTCPUDPPort $Value
                            if ($PortValid.IsValid -eq $false) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "Port"
                                $ErrorObject.Note = "Improper Port Value. Value Submited: $Value - ValueRange: 0-65535"
                            }
                            $ListItemDataType = "Int32"
                            $ListItemType = "Port"
                        }
                    }
                } else {
                    if ($Value -like "*,*" -Or $ItemType.tolower() -eq "portrange") {
                        # Pair of Integer for TCP/UDP Port
                        if ($Value.split(",").Count -ne 2) {
                            $ErrorObject.Error = $true
                            $ErrorObject.FieldType =  "PortRange"
                            $ErrorObject.QuantityMismatch =   $true
                            $ErrorObject.Note = "Quantity Mismatch.  Values Submited: $($Value.split(",").Count) - ValuesRequired: 2"
                        }
                        $Value.split(",").Trim() | ForEach-Object {
                            # Validate each port
                            $PortValid = Test-ValidTCPUDPPort $_
                            if ($PortValid.IsValid -eq $false) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "PortRange"
                                $ErrorObject.Note = "Improper PortRange Value. Value Submited: $_ - ValueRange: 0-65535"
                            }
                        }
                        # Set List metadata type
                        $ListItemDataType = "PortRange"
                        $ListItemType = "PortRange"
                    } else {
                        # Validate TCP/UDP Port
                        $PortValid = Test-ValidTCPUDPPort $Value
                        if ($PortValid.IsValid -eq $false) {
                            $ErrorObject.Error = $true
                            $ErrorObject.FieldType =  "Port"
                            $ErrorObject.Note = "Improper Port Value. Value Submited: $Value - ValueRange: 0-65535"
                        }
                        $ListItemDataType = "Int32"
                        $ListItemType = "Port"
                    }
                }
            }
            GeneralValue {
                $ListItemDataType = "String"
                $ListItemType = "StringValue"
            }
            Identity {
                $ListItemDataType = "Int32"
                $ListItemType = "Identity"
            }
            Host {
                # If ItemType is not defined, attempt to determine the item type.
                if (!$ItemType) {
                    # Reference for Integer Cast
                    $_int = 1                  
                    if ($Value -is [array]) {
                        if ($Value[0].split(",").Count -gt 1) {
                            Write-Verbose "[$Me]: Host:ItemType - More than one value present.  Value set as IPRange."
                            $ItemType = "iprange"
                        } elseif (($Value[0] -as [IPAddress] -as [Bool]) -eq $true) {
                            Write-Verbose "[$Me]: Host:ItemType - Value parses as IP Address."
                            $ItemType = "ip"
                        } elseif ([int]::TryParse($Value[0], [ref]$_int)) {
                            Write-Verbose "[$Me]: Host:ItemType - Value parses as knownhost integer."
                            $ItemType = "knownhost"
                        } else {
                            Write-Verbose "[$Me]: Host:ItemType - Value set as hostname string."
                            $ItemType = "hostname"
                        }
                    } else {
                        if ($Value.split(",").Count -gt 1) {
                            Write-Verbose "[$Me]: Host:ItemType - More than one value present.  Value set as IPRange."
                            $ItemType = "iprange"
                        } elseif (($Value -as [IPAddress] -as [Bool]) -eq $true) {
                            Write-Verbose "[$Me]: Host:ItemType - Value parses as IP Address."
                            $ItemType = "ip"
                        } elseif ([int]::TryParse($Value, [ref]$_int)) {
                            Write-Verbose "[$Me]: Host:ItemType - Value parses as knownhost integer."
                            $ItemType = "knownhost"
                        } else {
                            Write-Verbose "[$Me]: Host:ItemType - Value set as hostname string."
                            $ItemType = "hostname"
                        }
                    }
                } 
                switch ($ItemType.ToLower()) {
                    knownhost {  
                        $ListItemDataType = "Int32"
                        $ListItemType = "KnownHost" 
                        # Until a method of looking up KnownHost from Int32 this ListType is not supported.
                        $ErrorObject.Error = $true
                        $ErrorObject.FieldType = $ListItemType
                        $ErrorObject.Note = "ListType KnownHost is currently not supported"
                    }
                    hostname {
                        $ListItemDataType = "String"
                        $ListItemType = "HostName" 
                    }
                    iprange {
                        if ($Value -is [array]) {
                            ForEach ($Entry in $Value) {
                                if ($Entry.split(",").Count -ne 2) {
                                    $ErrorObject.Error = $true
                                    $ErrorObject.FieldType =  "IPRange"
                                    $ErrorObject.QuantityMismatch =   $true
                                    $ErrorObject.Note = "Quantity Mismatch.  Values Submited: $($Entry.split(",").Count) - ValuesRequired: 2"
                                }
                                $Entry.split(",").Trim() | ForEach-Object {
                                    # Validate each IP Address
                                    $IPValid = $_ -as [IPAddress] -as [Bool]
                                    if ($IPValid -eq $false) {
                                        $ErrorObject.Error = $true
                                        $ErrorObject.FieldType =  "IPRange"
                                        $ErrorObject.TypeMismatch = $true
                                        $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                                    }
                                }
                                # Remove spaces from Entry
                                $Entry = $Entry.Replace(" ","")
                            } 
                        } else { 
                            # Range of IP Addresses
                            if ($Value.split(",").Count -ne 2) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "IPRange"
                                $ErrorObject.QuantityMismatch =   $true
                                $ErrorObject.Note = "Quantity Mismatch.  Values Submited: $($Value.split(",").Count) - ValuesRequired: 2"
                            }
                            $Value.split(",").Trim() | ForEach-Object {
                                # Validate each IP Address
                                $IPValid = $_ -as [IPAddress] -as [Bool]
                                if ($IPValid -eq $false) {
                                    $ErrorObject.Error = $true
                                    $ErrorObject.FieldType =  "IPRange"
                                    $ErrorObject.TypeMismatch = $true
                                    $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                                }
                            }
                            # Remove all spaces from Value to support type IPRange
                            $Value = $Value.Replace(" ","")
                        }
                        $ListItemDataType = "IPRange"
                        $ListItemType = "IPRange" 
                    }
                    ip {
                        if ($Value -is [array]) {
                            ForEach ($Entry in $Value) {
                                # Validate IP Address format
                                $IPValid = $Entry -as [IPAddress] -as [Bool]
                                if ($IPValid -eq $false) {
                                    $ErrorObject.Error = $true
                                    $ErrorObject.FieldType =  "IP"
                                    $ErrorObject.TypeMismatch = $true
                                    $ErrorObject.Note = "Type Mismatch.  Values Submited: $Entry - Type Required: IPv4/IPv6 Address"
                                }
                            }
                        } else {
                            # Validate IP Address format
                            $IPValid = $Value -as [IPAddress] -as [Bool]
                            if ($IPValid -eq $false) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "IP"
                                $ErrorObject.TypeMismatch = $true
                                $ErrorObject.Note = "Type Mismatch.  Values Submited: $Value - Type Required: IPv4/IPv6 Address"
                            }
                        }

                        $ListItemDataType = "IP"
                        $ListItemType = "IP" 
                    }
                    Default {

                    }
                }
            }
            IP {
                # Validate IP Address format
                if ($Value -is [array]) {
                    ForEach ($Entry in $Value) {
                        $IPValid = $Entry -as [IPAddress] -as [Bool]
                        Write-Verbose "[$Me] IPValid: $IPValid"
                        if ($IPValid -eq $false) {
                            $ErrorObject.Error = $true
                            $ErrorObject.FieldType =  "IP"
                            $ErrorObject.TypeMismatch = $true
                            $ErrorObject.Note = "Type Mismatch.  Values Submited: $Entry - Type Required: IPv4/IPv6 Address"
                        }
                    }
                } else {
                    $IPValid = $Value -as [IPAddress] -as [Bool]
                    Write-Verbose "[$Me] IPValid: $IPValid"
                    if ($IPValid -eq $false) {
                        $ErrorObject.Error = $true
                        $ErrorObject.FieldType =  "IP"
                        $ErrorObject.TypeMismatch = $true
                        $ErrorObject.Note = "Type Mismatch.  Values Submited: $Value - Type Required: IPv4/IPv6 Address"
                    }
                }
                $ListItemDataType = "IP"
                $ListItemType = "IP"
            }
            IPRange {
                # Range of IP Addresses
                if ($Value -is [array]) {
                    ForEach ($Entry in $Value) {
                        if ($Entry.split(",").Count -ne 2) {
                            $ErrorObject.Error = $true
                            $ErrorObject.FieldType =  "IPRange"
                            $ErrorObject.QuantityMismatch =   $true
                            $ErrorObject.Note = "Quantity Mismatch.  Values Submited: $($Entry.split(",").Count) - ValuesRequired: 2"
                        }
                        $Entry.split(",").Trim() | ForEach-Object {
                            # Validate each IP Address
                            $IPValid = $_ -as [IPAddress] -as [Bool]
                            if ($IPValid -eq $false) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "IPRange"
                                $ErrorObject.TypeMismatch = $true
                                $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                            }
                        }
                        # Remove spaces from Entry
                        $Entry = $Entry.Replace(" ","")
                    } 
                } else {
                    if ($Value.split(",").Count -ne 2) {
                        $ErrorObject.Error = $true
                        $ErrorObject.FieldType =  "IPRange"
                        $ErrorObject.QuantityMismatch =   $true
                        $ErrorObject.Note = "Quantity Mismatch.  Values Submited: $($Value.split(",").Count) - ValuesRequired: 2"
                    }
                    $Value.split(",").Trim() | ForEach-Object {
                        # Validate each IP Address
                        $IPValid = $_ -as [IPAddress] -as [Bool]
                        if ($IPValid -eq $false) {
                            $ErrorObject.Error = $true
                            $ErrorObject.FieldType =  "IPRange"
                            $ErrorObject.TypeMismatch = $true
                            $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                        }
                    }
                    # Remove spaces from Value
                    $Value = $Value.Replace(" ","")
                }
                $ListItemDataType = "IPRange"
                $ListItemType = "IPRange"
            }
            User {
                $ListItemDataType = "String"
                $ListItemType = "StringValue"
            }
            Default {}
        }

        #$ExpDate = (Get-Date).AddDays(7).ToString("yyyy-MM-dd")

        # Request Setup
        $Method = $HttpMethod.Post
        $RequestUrl = $BaseUrl + "/lists/$Guid/items/"

        if ($Value -is [array]) {
            $ItemValues = [PSCustomObject]@{        }
            $Items = @()
            ForEach ($Entry in $Value) {
                $Items += @{
                    displayValue = 'List'
                    expirationDate = $ExpDate
                    isExpired =  $false
                    isListItem = $false
                    isPattern = $false
                    listItemDataType = $ListItemDataType
                    listItemType = $ListItemType
                    value = $Entry
                }
            }
            $ItemValues | Add-Member -NotePropertyName items -NotePropertyValue $Items
            # Check length of Items to Add to List
            if ($ItemValues.length -gt 1000) {
                #Split Items into multiple body contents
                # TO DO
                Write-Host "Over 1000 items submitted.  Currently not supported."
            } else {
                # Establish Body Contents
                $BodyContents = $ItemValues
            }
        } else {
            # Request Body
            $BodyContents = [PSCustomObject]@{
                items = @([PSCustomObject]@{
                        displayValue = 'List'
                        expirationDate = $ExpDate
                        isExpired =  $false
                        isListItem = $false
                        isPattern = $false
                        listItemDataType = $ListItemDataType
                        listItemType = $ListItemType
                        value = $Value
                        valueAsListReference = [PSCustomObject]@{}
                    }
                )
            }
        }
        

        $Body = $BodyContents | ConvertTo-Json -Depth 5 -Compress
        Write-Verbose "[$Me] Request Body:`n$Body"

        # Check for Object Errors
        if ( $ErrorObject.Error -eq $true) {
            return $ErrorObject
        } elseif ($Value -is [array]) {
            # No Duplicate checking for array of items
            # Send Request
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
        } else {
            # Check for Duplicates for single items
            $ExistingValue = Test-LrListValue -Name $Guid -Value $Value
            if (($ExistingValue.IsPresent -eq $false) -and ($ExistingValue.ListValid -eq $true)) {
                # Send Request
                if ($PSEdition -eq 'Core'){
                    try {
                        $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -Body $Body -SkipCertificateCheck
                    }
                    catch [System.Net.WebException] {
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
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Value = $ExistingValue.Value
                $ErrorObject.FieldType = $ListItemType
                $ErrorObject.Duplicate = $true
                $ErrorObject.Note = "Duplicate Value.  Value: $Value"
                return $ErrorObject
            }
        }  
        return $Response
    }
    
    End { }
}