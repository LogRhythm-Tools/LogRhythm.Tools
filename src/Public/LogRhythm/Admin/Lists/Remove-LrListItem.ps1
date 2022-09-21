using namespace System
using namespace System.IO
using namespace System.Net
using namespace System.Collections.Generic

Function Remove-LrListItem {
 <#
    .SYNOPSIS
        Remove the provided value to the specified list from LogRhythm.
    .DESCRIPTION
        Remove-LrListItem removes the supplied object to the specified list.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Identity
        [System.String] (Name or Guid) or [System.Guid]
        Specifies a LogRhythm list object by providing one of the following property values:
          + List Name (as System.String), e.g. "LogRhythm: Suspicious Hosts"
          + List Guid (as System.String or System.Guid), e.g. D378A76F-1D83-4714-9A7C-FC04F9A2EB13
    .PARAMETER Value
        The value to be removed to the specified LogRhythm List.
    .PARAMETER ItemType
        For use with Lists that support multiple item types.  Add-LrListItem will attempt to auto-define
        this value.  This parameter enables setting the ItemType.
    .PARAMETER LoadListItems
        LoadListItems adds the Items property to the return of the PSCustomObject representing the 
        specified LogRhythm List when an item is successfully removed.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .INPUTS
        [System.Object] -> Name
        [System.String[array]] -> Value     The Value parameter can be provided via the PowerShell pipeline as single value or array of values.
        [System.String] -> ItemType
        [System.Switch] -> LoadListItems
    .OUTPUTS
        PSCustomObject representing the specified LogRhythm List.
        If a Value parameter error is identified, a PSCustomObject is returned providing details
        associated to the error.
    .EXAMPLE
        PS C:\> Remove-LrListItem -Name srfIP -Value 192.168.5.20 -PassThru
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
    .EXAMPLE 
        Get-RfIPRiskList -List "Large" -IPv4 -ValuesOnly | Remove-LrListItem -Name "srf_IPAddress"
    .EXAMPLE 
        Error output example:

        PS C:\> Remove-LrListItem -Name srfIP -Value 192.168.5.1
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
    .EXAMPLE
        PS C:\> Remove-LrListItem -Name srfIP -Value 192.168.5.20

    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [object] $Name,

        
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 1)]
        [string[]] $Value,


        [Parameter(Mandatory = $false, Position = 2)]
        [ValidateSet('Application','Classification', 'CommonEvent', 'Host', 'Location', 'MsgSource', 
        'MsgSourceType', 'MPERule', 'Network', 'User', 'GeneralValue', 'Entity', 'RootEntity', 'IP',
        'IPRange', 'Identity',  ignorecase=$true)]
        [string] $ItemType,


        [Parameter(Mandatory = $false, Position = 3)]
        [switch] $LoadListItems,

                                        
        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $PassThru,


        [Parameter(Mandatory = $false, Position = 5)]
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
        
        if ($LoadListItems) {
            $Headers.Add("loadListItems",$LoadListItems)
        }

        #$ExpDate = (Get-Date).AddDays(7).ToString("yyyy-MM-dd")

        # Define HTTP Method
        $Method = $HttpMethod.Delete

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
            Raw                   =   $null
        }

        # Process Name
        if (($Name.GetType() -eq [System.Guid]) -Or (Test-Guid $Name)) {
            $TargetList = Get-LrList -name $Name.ToString()
            if ($TargetList.Error -eq $true) {
                return $TargetList
            }
        } else {
            $TargetList = Get-LrLists -Name $Name.ToString() -Exact
            if ($TargetList.Error -eq $true) {
                return $TargetList
            }
        }

        # Set List Type
        $LrListType = $TargetList.listType

        # List Guid
        $ListGuid = $TargetList.Guid

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
                                return $ErrorObject
                            }
                            $Entry.split(",").Trim() | ForEach-Object {
                                # Validate each port
                                $PortValid = Test-ValidTCPUDPPort $_
                                if ($PortValid.IsValid -eq $false) {
                                    $ErrorObject.Error = $true
                                    $ErrorObject.FieldType =  "PortRange"
                                    $ErrorObject.Note = "Improper PortRange Value. Value Submited: $_ - ValueRange: 0-65535"
                                    return $ErrorObject
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
                                return $ErrorObject
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
                            return $ErrorObject
                        }
                        $Value.split(",").Trim() | ForEach-Object {
                            # Validate each port
                            $PortValid = Test-ValidTCPUDPPort $_
                            if ($PortValid.IsValid -eq $false) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "PortRange"
                                $ErrorObject.Note = "Improper PortRange Value. Value Submited: $_ - ValueRange: 0-65535"
                                return $ErrorObject
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
                            return $ErrorObject
                        }
                        $ListItemDataType = "Int32"
                        $ListItemType = "Port"
                    }
                }
            }
            Entity {
                $ListItemDataType = "Int32"
                $ListItemType = "Entity"
            }
            GeneralValue {
                $ListItemDataType = "String"
                $ListItemType = "StringValue"
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
                        return $ErrorObject
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
                                    return $ErrorObject
                                }
                                $Entry.split(",").Trim() | ForEach-Object {
                                    # Validate each IP Address
                                    $IPValid = $_ -as [IPAddress] -as [Bool]
                                    if ($IPValid -eq $false) {
                                        $ErrorObject.Error = $true
                                        $ErrorObject.FieldType =  "IPRange"
                                        $ErrorObject.TypeMismatch = $true
                                        $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                                        return $ErrorObject
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
                                return $ErrorObject
                            }
                            $Value.split(",").Trim() | ForEach-Object {
                                # Validate each IP Address
                                $IPValid = $_ -as [IPAddress] -as [Bool]
                                if ($IPValid -eq $false) {
                                    $ErrorObject.Error = $true
                                    $ErrorObject.FieldType =  "IPRange"
                                    $ErrorObject.TypeMismatch = $true
                                    $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                                    return $ErrorObject
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
                                    return $ErrorObject
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
                                return $ErrorObject
                            }
                        }

                        $ListItemDataType = "IP"
                        $ListItemType = "IP" 
                    }
                    Default {

                    }
                }
            }
            Identity {
                $ListItemDataType = "Int32"
                $ListItemType = "Identity"
            }
            IP {
                # Validate IP Address format
                if ($Value -is [array]) {
                    ForEach ($Entry in $Value) {
                        $IPValid = $Entry -as [IPAddress] -as [Bool]
                        Write-Verbose "[$Me]: IPValid: $IPValid"
                        if ($IPValid -eq $false) {
                            $ErrorObject.Error = $true
                            $ErrorObject.FieldType =  "IP"
                            $ErrorObject.TypeMismatch = $true
                            $ErrorObject.Note = "Type Mismatch.  Values Submited: $Entry - Type Required: IPv4/IPv6 Address"
                            return $ErrorObject
                        }
                    }
                } else {
                    $IPValid = $Value -as [IPAddress] -as [Bool]
                    Write-Verbose "[$Me]: IPValid: $IPValid"
                    if ($IPValid -eq $false) {
                        $ErrorObject.Error = $true
                        $ErrorObject.FieldType =  "IP"
                        $ErrorObject.TypeMismatch = $true
                        $ErrorObject.Note = "Type Mismatch.  Values Submited: $Value - Type Required: IPv4/IPv6 Address"
                        return $ErrorObject
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
                            return $ErrorObject
                        }
                        $Entry.split(",").Trim() | ForEach-Object {
                            # Validate each IP Address
                            $IPValid = $_ -as [IPAddress] -as [Bool]
                            if ($IPValid -eq $false) {
                                $ErrorObject.Error = $true
                                $ErrorObject.FieldType =  "IPRange"
                                $ErrorObject.TypeMismatch = $true
                                $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                                return $ErrorObject
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
                        return $ErrorObject
                    }
                    $Value.split(",").Trim() | ForEach-Object {
                        # Validate each IP Address
                        $IPValid = $_ -as [IPAddress] -as [Bool]
                        if ($IPValid -eq $false) {
                            $ErrorObject.Error = $true
                            $ErrorObject.FieldType =  "IPRange"
                            $ErrorObject.TypeMismatch = $true
                            $ErrorObject.Note = "Type Mismatch.  Values Submited: $_ - Type Required: IPv4/IPv6 Address"
                            return $ErrorObject
                        }
                    }
                    # Remove spaces from Value
                    $Value = $Value.Replace(" ","")
                }
                $ListItemDataType = "IPRange"
                $ListItemType = "IPRange"
            }
            Location {
                $ListItemDataType = "Int32"
                $ListItemType = "Location"
            }
            MPERule {
                $ListItemDataType = "Int32"
                $ListItemType = "MPERule"
            }
            RootEntity {
                $ListItemDataType = "Int32"
                $ListItemType = "RootEntity"
            }
            User {
                $ListItemDataType = "String"
                $ListItemType = "StringValue"
            }
            MsgSource {
                $ListItemDataType = "Int32"
                $ListItemType = "MsgSource"
            }
            MsgSourceType {
                $ListItemDataType = "Int32"
                $ListItemType = "MsgSourceType"
            }
            Network {
                # Entity Network
                # Only accepts NetworkIDs
                $ListItemDataType = "Int32"
                $ListItemType = "Network"
            }
            Default {}
        }

        if ($Value -is [array]) {
            $Items = [list[object]]::new()
            $ItemValues = [PSCustomObject]@{}
            ForEach ($Entry in $Value) {
                $ItemValue = [PSCustomObject]@{
                        displayValue = 'List'
                        expirationDate = $ExpDate
                        isExpired =  $false
                        isListItem = $false
                        isPattern = $false
                        listItemDataType = $ListItemDataType
                        listItemType = $ListItemType
                        value = $Entry
                }
                $Items.add($ItemValue)
            }
            $ItemValues | Add-Member -NotePropertyName items -NotePropertyValue $Items
            # Check length of Items to Add to List
            if ($ItemValues.length -gt 1000) {
                #Split Items into multiple body contents
                # TO DO
                $ErrorObject.Error = $true
                $ErrorObject.Note = "Over 1000 items submitted.  Currently not supported."
                return $ErrorObject
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
        
        # Set Request Body
        $Body = $BodyContents | ConvertTo-Json -Depth 5 -Compress
        

        # Set HTTP Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/lists/$ListGuid/items/"

        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        # Check for Object Errors
        if ($Value -is [array]) {
            # No Duplicate checking for array of items
            # Send Request
            $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
            if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
                return $Response
            }
        } else {
            # Check for Duplicates for single items
            $ExistingValue = Test-LrListValue -Name $ListGuid -Value $Value
            if (($ExistingValue.IsPresent -eq $false) -and ($ExistingValue.ListValid -eq $true)) {
                # Send Request
                $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
                if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
                    return $Response
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

        if ($PassThru) {
            return $Response
        }
    }
    
    End { }
}