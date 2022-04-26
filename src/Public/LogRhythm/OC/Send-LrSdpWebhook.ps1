using namespace System
using namespace System.IO
using namespace System.Collections.Generic
Function Send-LrSdpWebhook {
    <#
    .SYNOPSIS
        Submits a log message in to a LogRhythm Open Collector Webhook Beat for log ingestion.
    .EXAMPLE
        PS C:\> Send-LrSdpWebhook -Account 'ehart' -sip '192.168.5.6' -dip '192.168.5.7' -OCUrl 'http://172.17.5.20:8085/webhook' -fqbn 'webhook_SDPGenericExample'
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
        account
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [String] $account,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [String] $action,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Int32] $amount,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [String] $command,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [String] $cve,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [String] $dinterface,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [String] $dip,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 7)]
        [String] $dmac,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 8)]
        [String] $dname,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 9)]
        [String] $dnatip,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 10)]
        [String] $dnatport,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 11)]
        [String] $domainimpacted,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 12)]
        [String] $domainorigin,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 13)]
        [int32] $dport,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 14)]
        [String] $group,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 15)]
        [String] $hash,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 16)]
        [int32] $kilobytes,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 17)]
        [int32] $kilobytesin,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 18)]
        [int32] $kilobytesout,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 19)]
        [String] $login,
        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 20)]
        [int32] $milliseconds,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 21)]
        [int32] $minutes,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 22)]
        [String] $object,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 23)]
        [String] $objectname,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 24)]
        [String] $objecttype,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 25)]
        [int32] $packetsin,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 26)]
        [int32] $packetsout,
       
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 27)]
        [int32] $parentprocessid,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 28)]
        [String] $parentprocessname,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 29)]
        [String] $parentprocesspath,
        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 30)]
        [String] $policy,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 31)]
        [String] $process,
        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 32)]
        [int32] $processid,
        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 33)]
        [string] $protname,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 34)]
        [int32] $protnum,
        
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 35)]
        [int32] $quantity,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 36)]
        [int32] $rate,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 37)]
        [String] $reason,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 38)]
        [String] $recipient,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 39)]
        [String] $responsecode,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 40)]
        [String] $result,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 41)]
        [int32] $seconds,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 42)]
        [String] $sender,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 43)]
        [String] $serialnumber,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 44)]
        [String] $session,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 45)]
        [String] $sessiontype,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 46)]
        [String] $severity,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 47)]
        [String] $sinterface,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 48)]
        [String] $sip,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 49)]
        [int32] $size,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 50)]
        [String] $smac,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 51)]
        [String] $sname,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 52)]
        [String] $snatip,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 53)]
        [String] $snatport,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 54)]
        [int32] $sport,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 55)]
        [String] $status,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 56)]
        [String] $subject,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 57)]
        [String] $tag1,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 58)]
        [String] $tag2,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 59)]
        [String] $tag3,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 60)]
        [String] $tag4,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 61)]
        [String] $tag5,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 62)]
        [String] $tag6,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 63)]
        [String] $tag7,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 64)]
        [String] $tag8,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 65)]
        [String] $tag9,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 66)]
        [String] $tag10,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 67)]
        [String] $threatid,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 68)]
        [String] $threatname,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 69)]
        [String] $time,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 70)]
        [String] $url,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 71)]
        [String] $useragent,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 72)]
        [String] $vendorinfo,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 73)]
        [String] $version,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 74)]
        [String] $vmid,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 75)]
        [String] $fqbn,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 76)]
        [String] $original_message,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 77)]
        [String] $OCUrl,

        [Parameter(Mandatory = $false, Position = 78)]
        [int32]$MaxRetries = 4,

        [Parameter(Mandatory = $false, Position = 79)]
        [int32]$RetryDelayMs = 250
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        
        # Request Setup
        if ($OCUrl) {
            $BaseUrl = $OCUrl
        } else {
            $BaseUrl = $LrtConfig.OC.BaseUrl
        }
        

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Content-Type","application/json")

        # Define HTTP Method
        $Method = $HttpMethod.post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Variables supporting HTTP Retry for 429 Error handling
        $RetryCounter = 0
    }

    Process {
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        # Establish Webhook Beat Source Define Parser key to enable JSON/JQ parsing to LogRhythm Metadata fields
        $OCLog = [PSCustomObject]@{
            whsdp = $true
        }

        if ($Account) { $OCLog | Add-Member -MemberType NoteProperty -Name 'account' -Value $Account -Force }
        if ($Action) { $OCLog | Add-Member -MemberType NoteProperty -Name 'action' -Value $Action -Force }
        if ($Amount) { $OCLog | Add-Member -MemberType NoteProperty -Name 'amount' -Value $Amount -Force }
        if ($Command) { $OCLog | Add-Member -MemberType NoteProperty -Name 'command' -Value $Command -Force }
        if ($Cve) { $OCLog | Add-Member -MemberType NoteProperty -Name 'cve' -Value $Cve -Force }
        if ($dinterface) { $OCLog | Add-Member -MemberType NoteProperty -Name 'dinterface' -Value $dinterface -Force }
        if ($dip) { $OCLog | Add-Member -MemberType NoteProperty -Name 'dip' -Value $dip -Force }
        if ($dmac) { $OCLog | Add-Member -MemberType NoteProperty -Name 'dmac' -Value $dmac -Force }
        if ($dname) { $OCLog | Add-Member -MemberType NoteProperty -Name 'dname' -Value $dname -Force }
        if ($dnatip) { $OCLog | Add-Member -MemberType NoteProperty -Name 'dnatip' -Value $dnatip -Force }
        if ($dnatport) { $OCLog | Add-Member -MemberType NoteProperty -Name 'dnatport' -Value $dnatport -Force }
        if ($domainimpacted) { $OCLog | Add-Member -MemberType NoteProperty -Name 'domainimpacted' -Value $domainimpacted -Force }
        if ($domainorigin) { $OCLog | Add-Member -MemberType NoteProperty -Name 'domainorigin' -Value $domainorigin -Force }
        if ($group) { $OCLog | Add-Member -MemberType NoteProperty -Name 'group' -Value $group -Force }
        if ($hash) { $OCLog | Add-Member -MemberType NoteProperty -Name 'hash' -Value $hash -Force }
        if ($kilobytes) { $OCLog | Add-Member -MemberType NoteProperty -Name 'kilobytes' -Value $kilobytes -Force }
        if ($kilobytesin) { $OCLog | Add-Member -MemberType NoteProperty -Name 'kilobytesin' -Value $kilobytesin -Force }
        if ($kilobytesout) { $OCLog | Add-Member -MemberType NoteProperty -Name 'kilobytesout' -Value $kilobytesout -Force }
        if ($login) { $OCLog | Add-Member -MemberType NoteProperty -Name 'login' -Value $login -Force }
        if ($milliseconds) { $OCLog | Add-Member -MemberType NoteProperty -Name 'milliseconds' -Value $milliseconds -Force }
        if ($minutes) { $OCLog | Add-Member -MemberType NoteProperty -Name 'minutes' -Value $minutes -Force }
        if ($object) { $OCLog | Add-Member -MemberType NoteProperty -Name 'object' -Value $object -Force }
        if ($objectname) { $OCLog | Add-Member -MemberType NoteProperty -Name 'objectname' -Value $objectname -Force }
        if ($objecttype) { $OCLog | Add-Member -MemberType NoteProperty -Name 'objecttype' -Value $objecttype -Force }
        if ($packetsin) { $OCLog | Add-Member -MemberType NoteProperty -Name 'packetsin' -Value $packetsin -Force }
        if ($packetsout) { $OCLog | Add-Member -MemberType NoteProperty -Name 'packetsout' -Value $packetsout -Force }
        if ($parentprocessid) { $OCLog | Add-Member -MemberType NoteProperty -Name 'parentprocessid' -Value $parentprocessid -Force }
        if ($parentprocessname) { $OCLog | Add-Member -MemberType NoteProperty -Name 'parentprocessname' -Value $parentprocessname -Force }
        if ($parentprocesspath) { $OCLog | Add-Member -MemberType NoteProperty -Name 'parentprocesspath' -Value $parentprocesspath -Force }
        if ($policy) { $OCLog | Add-Member -MemberType NoteProperty -Name 'policy' -Value $policy -Force }
        if ($process) { $OCLog | Add-Member -MemberType NoteProperty -Name 'process' -Value $process -Force }
        if ($processid) { $OCLog | Add-Member -MemberType NoteProperty -Name 'processid' -Value $processid -Force }
        if ($protname) { $OCLog | Add-Member -MemberType NoteProperty -Name 'protname' -Value $protname -Force }
        if ($protnum) { $OCLog | Add-Member -MemberType NoteProperty -Name 'protnum' -Value $protnum -Force }
        if ($quantity) { $OCLog | Add-Member -MemberType NoteProperty -Name 'quantity' -Value $quantity -Force }
        if ($rate) { $OCLog | Add-Member -MemberType NoteProperty -Name 'rate' -Value $rate -Force }
        if ($reason) { $OCLog | Add-Member -MemberType NoteProperty -Name 'reason' -Value $reason -Force }
        if ($recipient) { $OCLog | Add-Member -MemberType NoteProperty -Name 'recipient' -Value $recipient -Force }
        if ($responsecode) { $OCLog | Add-Member -MemberType NoteProperty -Name 'responsecode' -Value $responsecode -Force }
        if ($result) { $OCLog | Add-Member -MemberType NoteProperty -Name 'result' -Value $result -Force }
        if ($seconds) { $OCLog | Add-Member -MemberType NoteProperty -Name 'seconds' -Value $seconds -Force }
        if ($sender) { $OCLog | Add-Member -MemberType NoteProperty -Name 'sender' -Value $sender -Force }
        if ($serialnumber) { $OCLog | Add-Member -MemberType NoteProperty -Name 'serialnumber' -Value $serialnumber -Force }
        if ($session) { $OCLog | Add-Member -MemberType NoteProperty -Name 'session' -Value $session -Force }
        if ($sessiontype) { $OCLog | Add-Member -MemberType NoteProperty -Name 'sessiontype' -Value $sessiontype -Force }
        if ($severity) { $OCLog | Add-Member -MemberType NoteProperty -Name 'severity' -Value $severity -Force }
        if ($sinterface) { $OCLog | Add-Member -MemberType NoteProperty -Name 'sinterface' -Value $sinterface -Force }
        if ($sip) { $OCLog | Add-Member -MemberType NoteProperty -Name 'sip' -Value $sip -Force }
        if ($size) { $OCLog | Add-Member -MemberType NoteProperty -Name 'size' -Value $size -Force }
        if ($smac) { $OCLog | Add-Member -MemberType NoteProperty -Name 'smac' -Value $smac -Force }
        if ($sname) { $OCLog | Add-Member -MemberType NoteProperty -Name 'sname' -Value $sname -Force }
        if ($snatip) { $OCLog | Add-Member -MemberType NoteProperty -Name 'snatip' -Value $snatip -Force }
        if ($snatport) { $OCLog | Add-Member -MemberType NoteProperty -Name 'snatport' -Value $snatport -Force }
        if ($sport) { $OCLog | Add-Member -MemberType NoteProperty -Name 'sport' -Value $sport -Force }
        if ($status) { $OCLog | Add-Member -MemberType NoteProperty -Name 'status' -Value $status -Force }
        if ($subject) { $OCLog | Add-Member -MemberType NoteProperty -Name 'subject' -Value $subject -Force }
        if ($tag1) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag1' -Value $tag1 -Force }
        if ($tag2) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag2' -Value $tag2 -Force }
        if ($tag3) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag3' -Value $tag3 -Force }
        if ($tag4) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag4' -Value $tag4 -Force }
        if ($tag5) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag5' -Value $tag5 -Force }
        if ($tag6) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag6' -Value $tag6 -Force }
        if ($tag7) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag7' -Value $tag7 -Force }
        if ($tag8) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag8' -Value $tag8 -Force }
        if ($tag9) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag9' -Value $tag9 -Force }
        if ($tag10) { $OCLog | Add-Member -MemberType NoteProperty -Name 'tag10' -Value $tag10 -Force }
        if ($threatid) { $OCLog | Add-Member -MemberType NoteProperty -Name 'threatid' -Value $threatid -Force }
        if ($threatname) { $OCLog | Add-Member -MemberType NoteProperty -Name 'threatname' -Value $threatname -Force }
        if ($timestamp8601) { $OCLog | Add-Member -MemberType NoteProperty -Name 'timestamp.iso8601' -Value $timestamp8601 -Force }
        if ($timestampepoch) { $OCLog | Add-Member -MemberType NoteProperty -Name 'timestamp.epoch' -Value $timestampepoch -Force }
        if ($url) { $OCLog | Add-Member -MemberType NoteProperty -Name 'url' -Value $url -Force }
        if ($useragent) { $OCLog | Add-Member -MemberType NoteProperty -Name 'useragent' -Value $useragent -Force }
        if ($vendorinfo) { $OCLog | Add-Member -MemberType NoteProperty -Name 'vendorinfo' -Value $vendorinfo -Force }
        if ($version) { $OCLog | Add-Member -MemberType NoteProperty -Name 'version' -Value $version -Force }
        if ($vmid) { $OCLog | Add-Member -MemberType NoteProperty -Name 'vmid' -Value $vmid -Force }
        if ($fqbn) { $OCLog | Add-Member -MemberType NoteProperty -Name 'fullyqualifiedbeatname' -Value $fqbn -Force }
        if ($original_message) { $OCLog | Add-Member -MemberType NoteProperty -Name 'original_message' -Value $original_message -Force }

        # Establish Body Contents
        $Body = $OCLog | ConvertTo-Json -compress

        # Send Request
        Do {
            $RetryRequest = $false
            Try {
                $Response = Invoke-RestMethod $BaseUrl -Headers $Headers -Method $Method -Body $Body
            } Catch {
                if($_.Exception.Response.StatusCode.value__ -eq 429 ){
                    if($RetryCounter -ge $MaxRetries){
                        $RetryRequest = $false
                    } else {
                        $RetryCounter += 1
                        $RetryRequest = $true
                        Start-Sleep -Milliseconds $RetryDelayMs
                    }
                } else {
                    return $_
                }

            }
        } While ($RetryRequest)

        if ($PassThru) {
            return $Response
        }
    }

    End {
    }
}