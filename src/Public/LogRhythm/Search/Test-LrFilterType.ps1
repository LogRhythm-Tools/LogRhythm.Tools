using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Test-LrFilterType {
    <#
    .SYNOPSIS
        Validates provided LogRhythm List type is a valid List type.
    .DESCRIPTION
        The Test-LrListType cmdlet displays information about a given LogRhythm Unique 
        Case Identifier.
    .PARAMETER Id
        Test if List Type is valid based on ID property.
    .PARAMETER DisplayName
        Test if List Type is valid based on Display Name property.
    .PARAMETER EnumName
        Test if List Type is valid based on EnumName property.
    .OUTPUTS
        System.Object with IsValid, IdentifierValue, IdentifierType
    .EXAMPLE
        C:\PS> Test-LrIdentifierType "commonevent"
        IsValid    IdentifierValue    IdentifierType
        -------    ---------------    --------------
        True       tstr@example.com   Email
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position=0)]
        [int32] $Id,

        [Parameter(Mandatory = $false, Position=1)]
        [string] $DisplayName,

        [Parameter(Mandatory = $false, Position=2)]
        [string] $EnumName
    )
    Begin {
        $FieldFilterTypeEnum = @{
            53 = @{
                DisplayName = "Account by Active Directory Group"
                EnumName = "IDMGroupForAccount"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            44 = @{
                DisplayName = "Address"
                EnumName = "Address"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            64 = @{
                DisplayName = "Amount"
                EnumName = "Amount"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            97 = @{
                DisplayName = "Application List"
                EnumName = "Application"
                ValueType = "List Reference"
                ValueTypeEnum = 11
            }
            10 = @{
                DisplayName = "Classification"
                EnumName = "MsgClass"
                ValueType = "int32"
                ValueTypeEnum = 2
                # To Do get MessageClassification to Int mapping
            }
            112 = @{
                DisplayName = "Command"
                EnumName = "Command"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            11 = @{
                DisplayName = "Common Event"
                EnumName = "CommonEvent"
                ValueType = "int32"
                ValueTypeEnum = 2
                # To Do get CommonEvent to Int mapping
            }
            2 = @{
                DisplayName = "Direction"
                EnumName = "Direction"
                ValueType = "int32"
                ValueTypeEnum = 2
                # To Do get Direction to Int mapping
            }
            62 = @{
                DisplayName = "Duration"
                EnumName = "Duration"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            38 = @{
                DisplayName = "Group"
                EnumName = "Group"
                ValueType = "String"
                ValueTypeEnum = 4

            }
            58 = @{
                DisplayName = "Host (Impacted) KBytes In"
                EnumName = "BytesIn"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            59 = @{
                DisplayName = "Host (Impacted) KBytes Out"
                EnumName = "BytesOut"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            95 = @{
                DisplayName = "Host (Impacted) KBytes Total"
                EnumName = "BytesInOut"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            100 = @{
                DisplayName = "Host List (Impacted)"
                EnumName = "DHost"
                ValueType = "List Reference"
                ValueTypeEnum = 11
            }
            98 = @{
                DisplayName = "Host List (Origin or Impacted)"
                EnumName = "Host"
                ValueType = "List Reference"
                ValueTypeEnum = 11
            }
            99 = @{
                DisplayName = "Host List (Origin)"
                EnumName = "SHost"
                ValueType = "List Reference"
                ValueTypeEnum = 11
            }
            60 = @{
                DisplayName = "Host (Impacted) Packets Received"
                EnumName = "ItemsIn"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            61 = @{
                DisplayName = "Host (Impacted) Packets Sent"
                EnumName = "ItemsOut"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            96 = @{
                DisplayName = "Host (Impacted) Packets Total"
                EnumName = "ItemsInOut"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            25 = @{
                DisplayName = "Hostname (Imapcted)"
                EnumName = "DHostName"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            23 = @{
                DisplayName = "Hostname (Origin or Impacted)"
                EnumName = "HostName"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            24 = @{
                DisplayName = "Host (Origin)"
                EnumName = "SHostName"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            16 = @{
                DisplayName = "Known Application"
                EnumName = "KnownService"
                ValueType = "int32"
                ValueTypeEnum = 2
                # To Do get KnownService to Int mapping
            }
            108 = @{
                DisplayName = "Interface (Impacted)"
                EnumName = "DInterface"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            133 = @{
                DisplayName = "Interface (Origin or Impacted)"
                EnumName = "Interface"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            107 = @{
                DisplayName = "Interface (Origin)"
                EnumName = "SInterface"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            19 = @{
                DisplayName = "IP Address (Impacted)"
                EnumName = "DIP"
                ValueType = "IPAddress"
                ValueTypeEnum = 5
            }
            17 = @{
                DisplayName = "IP Address (Origin or Impacted)"
                EnumName = "IP"
                ValueType = "IPAddress"
                ValueTypeEnum = 5
            }
            18 = @{
                DisplayName = "IP Address (Origin)"
                EnumName = "SIP"
                ValueType = "IPAddress"
                ValueTypeEnum = 5
            }
            22 = @{
                DisplayName = "IP Address Range (Impacted)"
                EnumName = "DIPRange"
                ValueType = "IPAddressRange"
                ValueTypeEnum = 6
            }
            20 = @{
                DisplayName = "IP Address Range (Origin or Impacted)"
                EnumName = "IPRange"
                ValueType = "IPAddressRange"
                ValueTypeEnum = 6
            }
            21 = @{
                DisplayName = "IP Address Range (Origin)"
                EnumName = "SIPRange"
                ValueType = "IPAddressRange"
                ValueTypeEnum = 6
            }
            15 = @{
                DisplayName = "Known Host (Impacted)"
                EnumName = "KnownDHost"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            13 = @{
                DisplayName = "Known Host (Origin or Impacted)"
                EnumName = "KnownHost"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            14 = @{
                DisplayName = "Known Host (Origin)"
                EnumName = "KnownSHost"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            86 = @{
                DisplayName = @("Location (Impacted)", "Country (Impacted)", "Region (Impacted)")
                EnumName = "DLocation"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            87 = @{
                DisplayName = "Location (Origin or Impacted)"
                EnumName = "Location"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            85 = @{
                DisplayName = @("Location (Origin)", "Country (Origin)", "Region (Origin)")
                EnumName = "SLocation"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            7 = @{
                DisplayName = "Log Source"
                EnumName = "MsgSource"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            6 = @{
                DisplayName = "Log Source Entity"
                EnumName = "Entity"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            136 = @{
                DisplayName = "Log Source Root Entity"
                EnumName = "RootEntity"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            9 = @{
                DisplayName = "Log Source Type"
                EnumName = "MsgSourceType"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            104 = @{
                DisplayName = "MAC Address (Impacted)"
                EnumName = "DMAC"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            132 = @{
                DisplayName = "MAC Address (Origin or Impacted)"
                EnumName = "MAC"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            103 = @{
                DisplayName = "MAC Address (Origin)"
                EnumName = "SMAC"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            35 = @{
                DisplayName = "Log Message"
                EnumName = "Message"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            12 = @{
                DisplayName = "MPE Rule Name"
                EnumName = "MPERule"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            106 = @{
                DisplayName = "NAT IP Address (Impacted)"
                EnumName = "DNATIP"
                ValueType = "IPAddress"
                ValueTypeEnum = 5
            }
            126 = @{
                DisplayName = "NAT IP Address (Origin or Impacted)"
                EnumName = "NATIP"
                ValueType = "IPAddress"
                ValueTypeEnum = 5
            }
            105 = @{
                DisplayName = "NAT IP Address (Origin)"
                EnumName = "SNATIP"
                ValueType = "IPAddress"
                ValueTypeEnum = 5
            }
            125 = @{
                DisplayName = "NAT IP Address Range (Impacted)"
                EnumName = "DNATIPRange"
                ValueType = "IPAddressRange"
                ValueTypeEnum = 6
            }
            127 = @{
                DisplayName = "NAT IP Address Range (Origin or Impacted)"
                EnumName = "NATIPRange"
                ValueType = "IPAddressRange"
                ValueTypeEnum = 6
            }
            124 = @{
                DisplayName = "NAT IP Address Range (Origin)"
                EnumName = "SNATIPRange"
                ValueType = "IPAddressRange"
                ValueTypeEnum = 6
            }
            115 = @{
                DisplayName = "NAT TCP/UDP Port (Impacted)"
                EnumName = "DNATPort"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            130 = @{
                DisplayName = "NAT TCP/UDP Port (Origin or Impacted)"
                EnumName = "NATPort"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            114 = @{
                DisplayName = "NAT TCP/UDP Port (Origin)"
                EnumName = "SNATPort"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            129 = @{
                DisplayName = "NAT TCP/UDP Port Range (Impacted)"
                EnumName = "DNATPortRange"
                ValueType = "PortRange"
                ValueTypeEnum = 9
            }
            131 = @{
                DisplayName = "NAT TCP/UDP Port Range (Origin or Impacted)"
                EnumName = "NATPortRange"
                ValueType = "PortRange"
                ValueTypeEnum = 9
            }
            128 = @{
                DisplayName = "NAT TCP/UDP Port Range (Origin)"
                EnumName = "SNATPortRange"
                ValueType = "PortRange"
                ValueTypeEnum = 9
            }
            50 = @{
                DisplayName = "Network (Impacted)"
                EnumName = "DNetwork"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            51 = @{
                DisplayName = "Network (Origin or Impacted)"
                EnumName = "Network"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            49 = @{
                DisplayName = "Network (Origin)"
                EnumName = "SNetwork"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            34 = @{
                DisplayName = "Object"
                EnumName = "Object"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            113 = @{
                DisplayName = "Object Name"
                EnumName = "ObjectName"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            29 = @{
                DisplayName = "User (Origin)"
                EnumName = "Login"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            52 = @{
                DisplayName = "Origin Login by Active Directory Group"
                EnumName = "IDMGroupForLogin"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            3 = @{
                DisplayName = "Priority"
                EnumName = "Priority"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            41 = @{
                DisplayName = "Process Name"
                EnumName = "Process"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            109 = @{
                DisplayName = "Process ID"
                EnumName = "PID"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            28 = @{
                DisplayName = "Protocol"
                EnumName = "Protocol"
                ValueType = "int16"
                ValueTypeEnum = 1
            }
            63 = @{
                DisplayName = "Quantity"
                EnumName = "Quantity"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            65 = @{
                DisplayName = "Rate"
                EnumName = "Rate"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            32 = @{
                DisplayName = "Recipient"
                EnumName = "Recipient"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            31 = @{
                DisplayName = "Sender"
                EnumName = "Sender"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            40 = @{
                DisplayName = "Session"
                EnumName = "Session"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            110 = @{
                DisplayName = "Severity"
                EnumName = "Severity"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            66 = @{
                DisplayName = "Size"
                EnumName = "Size"
                ValueType = "Quantity"
                ValueTypeEnum = 10
            }
            33 = @{
                DisplayName = "Subject"
                EnumName = "Subject"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            27 = @{
                DisplayName = "TCP/UDP Port (Impacted)"
                EnumName = "DPort"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            45 = @{
                DisplayName = "TCP/UDP Port (Origin or Impacted)"
                EnumName = "Port"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            26 = @{
                DisplayName = "TCP/UDP Port (Origin)"
                EnumName = "SPort"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            47 = @{
                DisplayName = "TCP/UDP Port Range (Impacted)"
                EnumName = "DPortRange"
                ValueType = "PortRange"
                ValueTypeEnum = 9
            }
            48 = @{
                DisplayName = "TCP/UDP Port Range (Origin or Impacted)"
                EnumName = "PortRange"
                ValueType = "PortRange"
                ValueTypeEnum = 9
            }
            46 = @{
                DisplayName = "TCP/UDP Port Range (Origin)"
                EnumName = "SPortrange"
                ValueType = "PortRange"
                ValueTypeEnum = 9
            }
            42 = @{
                DisplayName = "URL"
                EnumName = "URL"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            30 = @{
                DisplayName = "User (Impacted)"
                EnumName = "Account"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            43 = @{
                DisplayName = "User (Origin or Impacted)"
                EnumName = "User"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            54 = @{
                DisplayName = "User By Active Directory Group"
                EnumName = "IDMGroupForUser"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            111 = @{
                DisplayName = "Version"
                EnumName = "Version"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            93 = @{
                DisplayName = "Zone (Origin)"
                EnumName = "SZone"
            }
            94 = @{
                DisplayName = "Zone (Impacted)"
                EnumName = "DZone"
            }
            1000 = @{
                DisplayName = "Filter Group"
                EnumName = "FilterGroup"
            }
            1001 = @{
                DisplayName = "Poly List Item"
                EnumName = "PolyListItem"
            }
            39 = @{
                DisplayName = "Domain (Impacted)"
                EnumName = "Domain"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            137 = @{
                DisplayName = "Domain (Origin)"
                EnumName = "DomainOrigin"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            138 = @{
                DisplayName = "Hash"
                EnumName = "Hash"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            139 = @{
                DisplayName = "Policy"
                EnumName = "Policy"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            140 = @{
                DisplayName = "VendorInfo"
                EnumName = "VendorInfo"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            141 = @{
                DisplayName = "Result"
                EnumName = "Result"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            142 = @{
                DisplayName = "Object Type"
                EnumName = "ObjectType"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            143 = @{
                DisplayName = "CVE"
                EnumName = "CVE"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            144 = @{
                DisplayName = "User Agent"
                EnumName = "UserAgent"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            145 = @{
                DisplayName = "Parent Process ID"
                EnumName = "ParentProcessId"
                ValueType = "int32"
                ValueTypeEnum = 2
            }
            146 = @{
                DisplayName = "Parent Process Name"
                EnumName = "ParentProcessName"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            147 = @{
                DisplayName = "Parent Process Path"
                EnumName = "ParentProcessPath"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            148 = @{
                DisplayName = "Serial Number"
                EnumName = "SerialNumber"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            149 = @{
                DisplayName = "Reason"
                EnumName = "Reason"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            150 = @{
                DisplayName = "Status"
                EnumName = "Status"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            151 = @{
                DisplayName = "Threat ID"
                EnumName = "ThreatId"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            152 = @{
                DisplayName = "Threat Name"
                EnumName = "ThreatName"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            153 = @{
                DisplayName = "Session Type"
                EnumName = "SessionType"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            154 = @{
                DisplayName = "Action"
                EnumName = "Action"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            155 = @{
                DisplayName = "Response Code"
                EnumName = "ResponseCode"
                ValueType = "String"
                ValueTypeEnum = 4
            }
            167 = @{
                DisplayName = "User (Origin) Identity"
                EnumName = "UserOriginIdentityID"
                ValueType = "ListReference"
                ValueTypeEnum = 11
            }
            160 = @{
                DisplayName = "User (Origin or Impacted) Identity"
                EnumName = "Identity"
                ValueType = "ListReference"
                ValueTypeEnum = 11
            }
            168 = @{
                DisplayName = "User (Impacted) Identity"
                EnumName = "ResponseCode"
                ValueType = "ListReference"
                ValueTypeEnum = 11
            }
            169 = @{
                DisplayName = "Sender Identity"
                EnumName = "SenderIdentityID"
                ValueType = "ListReference"
                ValueTypeEnum = 11
            }
            170 = @{
                DisplayName = "Recipient Identity"
                EnumName = "RecipientIdentityID"
                ValueType = "ListReference"
                ValueTypeEnum = 11
            }
        }
    }

    Process {
        # Define return object
        $OutObject = [PSCustomObject]@{
            IsValid       = $false
            id            = $null
            ValueType     = $null
            ValueTypeEnum = $null
            DisplayName   = $null
            EnumName      = $null
        }

        if ($Id) {
            if ($FieldFilterTypeEnum[$Id]) {
                $OutObject.IsValid = $true
                $OutObject.id = $Id
                $OutObject.DisplayName = $FieldFilterTypeEnum[$Id].DisplayName
                $OutObject.EnumName = $FieldFilterTypeEnum[$Id].EnumName
                $OutObject.ValueType = $FieldFilterTypeEnum[$Id].ValueType
                $OutObject.ValueTypeEnum = $FieldFilterTypeEnum[$Id].ValueTypeEnum
            } else {
                $OutObject.IsValid = $false
            }
        } elseif ($DisplayName) {
            $FieldFilterTypeEnum.keys | ForEach-Object {
                if ($($FieldFilterTypeEnum[$_].DisplayName) -like $DisplayName) {
                    $OutObject.IsValid = $true
                    $OutObject.id = $_
                    $OutObject.DisplayName = $FieldFilterTypeEnum[$_].DisplayName
                    $OutObject.EnumName = $FieldFilterTypeEnum[$_].EnumName
                    $OutObject.ValueType = $FieldFilterTypeEnum[$_].ValueType
                    $OutObject.ValueTypeEnum = $FieldFilterTypeEnum[$_].ValueTypeEnum
                }
            }
        } elseif ($EnumName) {
            $FieldFilterTypeEnum.keys | ForEach-Object {
                if ($($FieldFilterTypeEnum[$_].EnumName) -like $EnumName) {
                    $OutObject.IsValid = $true
                    $OutObject.id = $_
                    $OutObject.DisplayName = $FieldFilterTypeEnum[$_].DisplayName
                    $OutObject.EnumName = $FieldFilterTypeEnum[$_].EnumName
                    $OutObject.ValueType = $FieldFilterTypeEnum[$_].ValueType
                    $OutObject.ValueTypeEnum = $FieldFilterTypeEnum[$_].ValueTypeEnum
                }
            }
        }
        return $OutObject
    }
    
    End { }
}