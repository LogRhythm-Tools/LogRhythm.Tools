Function Get-PIFTypeName {
    <#
    .SYNOPSIS
        Get Summary Field Name from PIFType from an AIE Drilldown Object.
    .DESCRIPTION
        Gets the readable field name from the Summary Field Id. Note Summary Fields are 
        also called PIFs or "Primary Inspection Fields"
    .PARAMETER PIFType
        The Id associated with the Summary Field ID, which is contained in an
        AIE Drilldown Object returned from the LogRhythm API.
    .INPUTS
        System.Int32 -> PIFType
    .OUTPUTS
        System.String
    .EXAMPLE
        PS C:\> Get-PIFTypeName 24
        ---
        IP Address (Origin)
    .LINK
        https://community.logrhythm.com/t5/AI-Engine-Rules/AIE-Drilldown-API/m-p/44276
    #>

    [CmdletBinding()]
    Param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            Position = 0
        )]
        [int] $PIFType
    )


    Begin {
        $PIFTypes = @{
            1 = "Direction"
            2 = "Priority"
            3 = "Normal Message Date"
            4 = "First Normal Message Date"
            5 = "Last Normal Message Date"
            6 = "Count"
            7 = "MessageDate"
            8 = "Entity"
            9 = "Log Source"
            10 = "Log Source Host"
            11 = "Log Source Type"
            12 = "Log Class Type"
            13 = "Log Class"
            14 = "Common Event"
            15 = "MPE Rule"
            16 = "Source"
            17 = "Destination"
            18 = "Service"
            19 = "Known Host"
            20 = "Known Host (Origin)"
            21 = "Known Host (Impacted)"
            22 = "Known Service"
            23 = "IP"
            24 = "IP Address (Origin)"
            25 = "IP Address (Impacted)"
            26 = "Host Name"
            27 = "Host Name (Origin)"
            28 = "Host Name (Impacted)"
            29 = "Port (Origin)"
            30 = "Port (Impacted)"
            31 = "Protocol"
            32 = "User (Origin)"
            33 = "User (Impacted)"
            34 = "Sender"
            35 = "Recipient"
            36 = "Subject"
            37 = "Object"
            38 = "Vendor Message ID"
            39 = "Vendor Message Name"
            40 = "Bytes In"
            41 = "Bytes Out"
            42 = "Items In"
            43 = "Items Out"
            44 = "Duration"
            45 = "Time Start"
            46 = "Time End"
            47 = "Process"
            48 = "Amount"
            49 = "Quantity"
            50 = "Rate"
            51 = "Size"
            52 = "Domain (Impacted)"
            53 = "Group"
            54 = "URL"
            55 = "Session"
            56 = "Sequence"
            57 = "Network (Origin)"
            58 = "Network (Impacted)"
            59 = "Location (Origin)"
            60 = "Country (Origin)"
            61 = "Region (Origin)"
            62 = "City (Origin)"
            63 = "Location (Impacted)"
            64 = "Country (Impacted)"
            65 = "Region (Impacted)"
            66 = "City (Impacted)"
            67 = "Entity (Origin)"
            68 = "Entity (Impacted)"
            69 = "Zone (Origin)"
            70 = "Zone (Impacted)"
            72 = "Zone"
            73 = "User"
            74 = "Address"
            75 = "MAC"
            76 = "NATIP"
            77 = "Interface"
            78 = "NATPort"
            79 = "Entity (Impacted or Origin)"
            80 = "RootEntity"
            100 = "Message"
            200 = "MediatorMsgID"
            201 = "MARCMsgID"
            1040 = "MAC (Origin)"
            1041 = "MAC (Impacted)"
            1042 = "NATIP (Origin)"
            1043 = "NATIP (Impacted)"
            1044 = "Interface (Origin)"
            1045 = "Interface (Impacted)"
            1046 = "PID"
            1047 = "Severity"
            1048 = "Version"
            1049 = "Command"
            1050 = "ObjectName"
            1051 = "NATPort (Origin)"
            1052 = "NATPort (Impacted)"
            1053 = "Domain (Origin)"
            1054 = "Hash"
            1055 = "Policy"
            1056 = "Vendor Info"
            1057 = "Result"
            1058 = "Object Type"
            1059 = "CVE"
            1060 = "UserAgent"
            1061 = "Parent Process Id"
            1062 = "Parent Process Name"
            1063 = "Parent Process Path"
            1064 = "Serial Number"
            1065 = "Reason"
            1066 = "Status"
            1067 = "Threat Id"
            1068 = "Threat Name"
            1069 = "Session Type"
            1070 = "Action"
            1071 = "Response Code"
            1072 = "User (Origin) Identity ID"
            1073 = "User (Impacted) Identity ID"
            1074 = "Sender Identity ID"
            1075 = "Recipient Identity ID"
            1076 = "User (Origin) Identity"
            1077 = "User (Impacted) Identity"
            1078 = "Sender Identity"
            1079 = "Recipient Identity"
            1080 = "User (Origin) Identity Domain"
            1081 = "User (Impacted) Identity Domain"
            1082 = "Sender Identity Domain"
            1083 = "Recipient Identity Domain"
            1084 = "User (Origin) Identity Company"
            1085 = "User (Impacted) Identity Company"
            1086 = "Sender Identity Company"
            1087 = "Recipient Identity Company"
            1088 = "User (Origin) Identity Department"
            1089 = "User (Impacted) Identity Department"
            1090 = "Sender Identity Department"
            1091 = "Recipient Identity Department"
            1092 = "User (Origin) Identity Title"
            1093 = "User (Impacted) Identity Title"
            1094 = "Sender Identity Title"
            1095 = "Recipient Identity Title"
            10001 = "Source Or Destination"
            10002 = "Port (Origin or Impacted)"
            10003 = "Network (Origin or Impacted)"
            10004 = "Location (Origin or Impacted)"
            10005 = "Country (Origin or Impacted)"
            10006 = "Region (Origin or Impacted)"
            10007 = "City (Origin or Impacted)"
            10008 = "Bytes In/Out"
            10009 = "Items In/Out"
        }
    }


    Process {
        if ($PIFTypes[$PIFType]) {
            return $PIFTypes[$PIFType]
        } else {
            return "Unknown PIFType"
        }
    }


    End { }
}