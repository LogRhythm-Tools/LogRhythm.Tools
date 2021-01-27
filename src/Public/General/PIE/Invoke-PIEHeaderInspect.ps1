using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Inspects and enriches Header data as provided by PIE processing engine.
    .OUTPUTS
        PSCustomObject containing an enriched set of email header data.
    .EXAMPLE
        Invoke-PIEHeaderInspect -Headers $EvaluationResults.Headers
        ---
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Invoke-PIEHeaderInspect {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNull()]
        [Object]$Headers
    )

    Begin {
        $Regex_IPv6 = '(?<IPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?:\)|\s+)'
        $Regex_IPv4 = '(?<IPv4>\d{1,3}(\.\d{1,3}){3})(?:\)|\s+)'
        # from x by y
        $Regex_Received1 = '^from\s+(?<fromhost>(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))\s\((?<fromaddr>(?<fIPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?<fIPv4>\d{1,3}(\.\d{1,3}){3}))\)\s+by\s+(?<by>(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))\s(\((?<byaddr>(?<bIPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?<bIPv4>\d{1,3}(\.\d{1,3}){3}))\))?.*,\s(?<date>(([0-9])|([0-2][0-9])|([3][0-1]))\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{4})\s(?<time>[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}).*$'
        # by y
        $Regex_Received2 = '^by\s+(?<byhost>(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9]))(\s\((?<byaddr>(?<bIPv6>([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))|(?<bIPv4>\d{1,3}(\.\d{1,3}){3}))\))?\s+.*,\s(?<date>(([0-9])|([0-2][0-9])|([3][0-1]))\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{4})\s(?<time>[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}).*$'
    
        # Key fields: 
        # x-ms-exchange-organization-originalclientipaddress <public>
        # x-ms-exchange-organization-originalserveripaddress <private>
        #  authentication-results
        # dkin-signature
    }

    Process {
        # Object that represents the data points for URL Shortlink services
        $Header_Details = [PSCustomObject]@{
            received = $null
            mimeversion = $null
            dkim = [PSCustomObject]@{
                signature = $null
                verdict = $null
            }
            microsoft = [pscustomobject]@{}
        }

        # Process Received
        $ReceivedOutput = [List[object]]::new()
        $ReceivedData = $Headers | Where-Object -Property 'field' -like 'Received' | Sort-Object -Property Offset
        For ($i = 0; $i -lt $ReceivedData.Count; $i++) {
            $Header_Received = [PSCustomObject]@{
                field = $ReceivedData[$i].Field
                value = $ReceivedData[$i].Value
                position = $null
                step = $i
                from = [PSCustomObject]@{
                    hostname = $null
                    ipv4 = $null
                    ipv6  = $null
                    geolocation = $null
                }
                by = [PSCustomObject]@{
                    hostname = $null
                    ipv4 = $null
                    ipv6  = $null
                    geolocation = $null
                }
                timestamp = $null
                
            }

            $Received1 = ([regex]::Matches($ReceivedData[$i].Value, $Regex_Received1))
            if ($Received1) {
                ForEach ($RegexMatch in $Received1) {
                    # From:
                    $Header_Received.From.Hostname = $RegexMatch.Groups["fromhost"].Value
                    if ($RegexMatch.Groups["fIPv6"].Value) {
                        $Header_Received.From.IPv6 = $RegexMatch.Groups["fIPv6"].Value
                    }
                    if ($RegexMatch.Groups["fIPv4"].Value) {
                        $Header_Received.From.IPv4 = $RegexMatch.Groups["fIPv4"].Value
                    }

                    # By:
                    if ($RegexMatch.Groups["by"].Value) {
                        $Header_Received.By.Hostname = $RegexMatch.Groups["by"].Value
                    }
                    if ($RegexMatch.Groups["bIPv6"].Value) {
                        $Header_Received.By.IPv6 = $RegexMatch.Groups["bIPv6"].Value
                    }
                    if ($RegexMatch.Groups["bIPv4"].Value) {
                        $Header_Received.By.IPv4 = $RegexMatch.Groups["bIPv4"].Value
                    }

                    # Time:
                    $Timestamp = $RegexMatch.Groups["date"].Value + " " + $RegexMatch.Groups["time"].Value
                    $Header_Received.timestamp = [datetime]::parseexact($Timestamp, 'd MMM yyyy HH:mm:ss', $null)
                }
            }
            
            $Received2 = ([regex]::Matches($ReceivedData[$i].Value, $Regex_Received2))
            if ($Received2) {
                ForEach ($RegexMatch in $Received2) {
                    # By:
                    if ($RegexMatch.Groups["byhost"].Value) {
                        $Header_Received.By.Hostname = $RegexMatch.Groups["byhost"].Value
                    }
                    if ($RegexMatch.Groups["bIPv6"].Value) {
                        $Header_Received.By.IPv6 = $RegexMatch.Groups["bIPv6"].Value
                    }
                    if ($RegexMatch.Groups["bIPv4"].Value) {
                        $Header_Received.By.IPv4 = $RegexMatch.Groups["bIPv4"].Value
                    }

                    # Time:
                    $Timestamp = $RegexMatch.Groups["date"].Value + " " + $RegexMatch.Groups["time"].Value
                    $Header_Received.timestamp = [datetime]::parseexact($Timestamp, 'd MMM yyyy HH:mm:ss', $null)
                }
            }

            
            # Set Header delivery chain position
            if ($i -eq 0) {
                $Header_Received.Position = "Destination"
            } elseif ($i -eq ($ReceivedData.Count -1)) {
                $Header_Received.Position = "Origin"
            } else {
                $Header_Received.Position = "Intermediary"
            }

            if ($ReceivedOutput -NotContains $Header_Received) {
                $ReceivedOutput.Add($Header_Received)
            }
        }

        # Add data to HeaderOutput
        $Header_Details.Received = $ReceivedOutput


        # If the record contains x-forefront-antispam-report
        if ($Headers.field -contains 'x-forefront-antispam-report') {
            $MSAntispamData = $Headers | Where-Object -Property 'field' -like 'x-forefront-antispam-report'
            $MSAntispamParsed = $MSAntispamData.value.split(';') | ConvertFrom-Csv -Delimiter ':' -Header @("field", "value")

            # Baseline 
            $Header_MSAntiSpam = [PSCustomObject]@{
                Field = $MSAntispamData.Field
                Value = $MSAntispamData.Value
                CIP = $($MSAntispamParsed | Where-Object {$_.field -like "cip"} | Select-Object -ExpandProperty value)
            }

            # Add additional properties based on presence of values
            # CTRY: Source country as determiend by connecting IP address, may not be same as originating sending IP address.
            if ($MSAntispamParsed.field -contains 'CTRY') {
                $MSAntiSpam_CTRY = $MSAntispamParsed | Where-Object {$_.field -like "CTRY"} | Select-Object -ExpandProperty value
                $Header_MSAntiSpam | add-member -membertype NoteProperty -name "country" -value $MSAntiSpam_CTRY
            }

            # LANG: Language the message is written in.
            if ($MSAntispamParsed.field -contains 'LANG') {
                $MSAntiSpam_LANG = $MSAntispamParsed | Where-Object {$_.field -like "LANG"} | Select-Object -ExpandProperty value
                $Header_MSAntiSpam | add-member -membertype NoteProperty -name "language" -value $MSAntiSpam_LANG
            }

            # SCL: # SPAM Confidency Level
            if ($MSAntispamParsed.field -contains 'SCL') {
                $MSAntiSpam_SCL = $MSAntispamParsed | Where-Object {$_.field -like "SCL"} | Select-Object -ExpandProperty value
                $Header_MSAntiSpam | add-member -membertype NoteProperty -name "spamconfidence" -value $MSAntiSpam_SCL
            }

            # PTR: The PTR record, reverse DNS lookup of the Source IP Address.
            if ($MSAntispamParsed.field -contains 'PTR') {
                $MSAntiSpam_PTR = $MSAntispamParsed | Where-Object {$_.field -like "PTR"} | Select-Object -ExpandProperty value
                $Header_MSAntiSpam | add-member -membertype NoteProperty -name "ptr" -value $MSAntiSpam_PTR
            }

            # CAT: One of: BULK, DIMP, GIMP, HPHSH/HPHISH, HSPM, MALW, PHSH, SPM, SPOOF, UIMP, AMP, SAP, OSPM
            #  CAT is a big one.
            if ($MSAntispamParsed.field -contains 'CAT') {
                $MSAntiSpam_CAT = $MSAntispamParsed | Where-Object {$_.field -like "CAT"} | Select-Object -ExpandProperty value
                $Header_MSAntiSpam | add-member -membertype NoteProperty -name "category" -value $MSAntiSpam_CAT
            }

            # DIR: Inbound/Outbound
            if ($MSAntispamParsed.field -contains 'DIR') {
                $MSAntiSpam_DIR = $MSAntispamParsed | Where-Object {$_.field -like "DIR"} | Select-Object -ExpandProperty value
                $Header_MSAntiSpam | add-member -membertype NoteProperty -name "direction" -value $MSAntiSpam_DIR
            }

            # Add data to HeaderOutput
            $Header_Details.Microsoft | add-member -membertype NoteProperty -name "x-forefront-antispam-report" -value $Header_MSAntiSpam
        }


        # If the record contains mime-version
        if ($Headers.field -contains 'mime-version') {
            $Header_Details.MimeVersion = $($Headers | Where-Object -Property 'field' -like 'mime-version' | Select-Object -ExpandProperty value)
        }

        # If the record contains From
        if ($Headers.field -contains 'From') {
            $Header_Details | add-member -membertype NoteProperty "from" -Value $($Headers | Where-Object -Property 'field' -like 'from' | Select-Object -ExpandProperty value)
        }

        # If the record contains To
        if ($Headers.field -contains 'To') {
            $Header_Details | add-member -membertype NoteProperty "to" -Value $($Headers | Where-Object -Property 'field' -like 'to' | Select-Object -ExpandProperty value)
        }

        # If the record contains Subject
        if ($Headers.field -contains 'Subject') {
            $Header_Details | add-member -membertype NoteProperty "subject" -Value $($Headers | Where-Object -Property 'field' -like 'subject' | Select-Object -ExpandProperty value)
        }

        # If the record contains Message-Id
        if ($Headers.field -contains 'message-id') {
            $Header_Details | add-member -membertype NoteProperty "message-id" -Value $($Headers | Where-Object -Property 'field' -like 'message-id' | Select-Object -ExpandProperty value)
        }

        # If the record contains List-Unsubscribe
        if ($Headers.field -contains 'List-Unsubscribe') {
            $Header_Details | add-member -membertype NoteProperty "list-unsubscribe" -Value $($Headers | Where-Object -Property 'field' -like 'list-unsubscribe' | Select-Object -ExpandProperty value)
        }

        # If the record contains Reply-To
        if ($Headers.field -contains 'Reply-To') {

            $ReplyToValue = $($Headers | Where-Object -Property 'field' -like 'reply-to' | Select-Object -ExpandProperty value)

            if ($ReplyToValue -match '.*".*') {
                $ReplyToData = [PSCustomObject]@{
                    displayname = $ReplyToValue.Split("`"").Trim()[1]
                    email = $ReplyToValue.Split("`"").Trim()[2]
                }

                $Header_Details | add-member -membertype NoteProperty "reply-to" -Value $ReplyToData
            } else {
                $Header_Details | add-member -membertype NoteProperty "reply-to" -Value $ReplyToValue
            }
        }

        # If the record contains X-MS-Exchange-Organization-AuthSource
        if ($Headers.field -contains 'X-MS-Exchange-Organization-AuthSource') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-organization-authsource" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-organization-authsource' | Select-Object -ExpandProperty value)
        }

        # If the record contains X-MS-Has-Attach
        if ($Headers.field -contains 'X-MS-Has-Attach') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-has-attach" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-has-attach' | Select-Object -ExpandProperty value)
        }

        # If the record contains X-MS-Exchange-Organization-Network-Message-Id
        if ($Headers.field -contains 'X-MS-Exchange-Organization-Network-Message-Id') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-organization-network-message-id" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-organization-network-message-id' | Select-Object -ExpandProperty value)
        }

        # If the record contains X-MS-TNEF-Correlator
        if ($Headers.field -contains 'X-MS-TNEF-Correlator') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-tnef-correlator" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-tnef-correlator' | Select-Object -ExpandProperty value)
        }

        # If the record contains X-MS-Exchange-Organization-RecordReviewCfmType
        if ($Headers.field -contains 'X-MS-Exchange-Organization-RecordReviewCfmType') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-organization-recordreviewcfmtype" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-organization-recordreviewcfmtype' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-organization-originalclientipaddress
        if ($Headers.field -contains 'x-ms-exchange-organization-originalclientipaddress') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-organization-originalclientipaddress" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-organization-originalclientipaddress' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-organization-originalserveripaddress
        if ($Headers.field -contains 'x-ms-exchange-organization-originalserveripaddress') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-organization-originalserveripaddress" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-organization-originalserveripaddress' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-organization-submissionquotaskipped
        if ($Headers.field -contains 'x-ms-exchange-organization-submissionquotaskipped') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-organization-submissionquotaskipped" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-organization-submissionquotaskipped' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-publictraffictype
        if ($Headers.field -contains 'x-ms-publictraffictype') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-publictraffictype" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-publictraffictype' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-office365-filtering-correlation-id
        if ($Headers.field -contains 'x-ms-office365-filtering-correlation-id') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-office365-filtering-correlation-id" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-office365-filtering-correlation-id' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-traffictypediagnostic
        if ($Headers.field -contains 'x-ms-traffictypediagnostic') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-traffictypediagnostic" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-traffictypediagnostic' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-crosstenant-originalarrivaltime
        if ($Headers.field -contains 'x-ms-exchange-crosstenant-originalarrivaltime') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-crosstenant-originalarrivaltime" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-crosstenant-originalarrivaltime' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-crosstenant-fromentityheader
        if ($Headers.field -contains 'x-ms-exchange-crosstenant-fromentityheader') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-crosstenant-fromentityheader" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-crosstenant-fromentityheader' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-crosstenant-id
        if ($Headers.field -contains 'x-ms-exchange-crosstenant-id') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-crosstenant-id" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-crosstenant-id' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-transport-crosstenantheadersstamped
        if ($Headers.field -contains 'x-ms-exchange-transport-crosstenantheadersstamped') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-transport-crosstenantheadersstamped" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-transport-crosstenantheadersstamped' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-transport-endtoendlatency
        if ($Headers.field -contains 'x-ms-exchange-transport-endtoendlatency') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-transport-endtoendlatency" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-transport-endtoendlatency' | Select-Object -ExpandProperty value)
        }

        # If the record contains x-ms-exchange-crosstenant-network-message-id
        if ($Headers.field -contains 'x-ms-exchange-crosstenant-network-message-id') {
            $Header_Details.Microsoft | add-member -membertype NoteProperty "x-ms-exchange-crosstenant-network-message-id" -Value $($Headers | Where-Object -Property 'field' -like 'x-ms-exchange-crosstenant-network-message-id' | Select-Object -ExpandProperty value)
        }

        # If the record contains received-spf
        if ($Headers.field -contains 'received-spf') {
            $Header_Details | add-member -membertype NoteProperty "received-spf" -Value $($Headers | Where-Object -Property 'field' -like 'received-spf' | Select-Object -ExpandProperty value)
        }

        
        # If the record contains authentication-results
        if ($Headers.field -contains 'authentication-results') {
            $Header_Details | add-member -membertype NoteProperty "authentication-results" -Value $($Headers | Where-Object -Property 'field' -like 'authentication-results' | Select-Object -ExpandProperty value)
        }

        # If the record contains X-Hashtags
        if ($Headers.field -contains 'X-Hashtags') {
            $Header_Details | add-member -membertype NoteProperty "x-hashtags" -Value $($Headers | Where-Object -Property 'field' -like 'X-Hashtags' | Select-Object -ExpandProperty value)
        }



        Return $Header_Details
    }
}