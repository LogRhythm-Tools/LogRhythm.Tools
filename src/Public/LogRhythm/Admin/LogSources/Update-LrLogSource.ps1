using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrLogSource {
    <#
    .SYNOPSIS
        Update the Log Source Details for a specific existing log source record.
    .DESCRIPTION
        This cmdlet currently only supports a limited number of parameters.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [int]
        Specifies a LogRhythm Log Source object by providing one of the following property values:
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .PARAMETER Name
        [string] Represents the updated name value to apply to the log source record.
    .PARAMETER RecordStatus
        [string] Represents the record status value to apply to the log source record.
    .PARAMETER Status
        [string] Represents the status value to apply to the log source record.
    .PARAMETER FilePath
        [string] Represents the FilePath value to apply to the log source record.
    .PARAMETER maxMsgCount
        [int] Represents the maxMsgCount value to apply to the log source record.
    .PARAMETER PassThru
        Switch paramater that will enable the return of the output object from the cmdlet.
    .OUTPUTS
        Success: No Output
        Error: PSCustomObject representing error details.
        PassThru: PSCustomObject representing LogRhythm Log Source record and its updated contents.
    .EXAMPLE
       Update-LrLogSource -Id 64 -FilePath 'tam-dc:Security' -maxMsgCount 1000 -PassThru

        id                       : 64
        systemMonitorId          : 46
        name                     : TAM-DC WinEvtXML - Security
        host                     : @{id=2114; name=TAM-DC}
        entity                   : @{id=1; name=Primary Site}
        logSourceType            : @{id=1000639; name=MS Windows Event Logging XML - Security}
        mpePolicy                : @{id=-1000000020; name=LogRhythm Default v2.0}
        recordStatus             : Active
        status                   : Enabled
        isVirtual                : False
        logMartMode              : 13627389
        isLoadBalanced           : False
        mpeProcessingMode        : EventForwardingEnabled
        isArchivingEnabled       : True
        maxMsgCount              : 1000
        defMsgTTLValue           : 0
        dateUpdated              : 2022-05-26T17:14:31.703Z
        isSilentLogSourceEnabled : False
        filePath                 : tam-dc:Security
        cryptoMode               : 0
        signMode                 : 0
        defMsgTTL                : 0
        defMsgArchiveMode        : Override_Archive
        msgPerCycle              : 1000
        collectionDepth          : 0
        udlaStateFieldType       : Increment
        parameter1               : 0
        parameter2               : 21600
        parameter3               : 43200
        parameter4               : 0
        recursionDepth           : 0
        isDirectory              : False
        compressionType          : none
        collectionThreadTimeout  : 120
        virtualSourceSortOrder   : 0
        virtualSourceCatchAllID  : 0
        persistentConnection     : False
        autoAcceptanceRuleId     : Manual
        maxLogDate               : 2022-04-12T19:02:00.737Z
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNull()]
        [int32] $Id,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $Name,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidateSet('Active','Retired', ignorecase=$true)]
        [string] $RecordStatus,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateSet('Enabled','Disabled', 'Unregistered', ignorecase=$true)]
        [string] $Status,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [string] $FilePath,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [ValidateRange(1, 10000)]
        [int32] $maxMsgCount,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [int32] $MpePolicyId,

        [Parameter(Mandatory = $false, Position = 7)]
        [switch] $PassThru,

        [Parameter(Mandatory = $false, Position = 8)]
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

        # Value Testing Paramater
        $_int = 0

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Value                 =   $Id
            Raw                   =   $null
        }

        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7\.[0-7]\.\d+') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.8.0 and greater."
            return $ErrorObject
        }

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $Guid = $Id
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $LogSourceLookup = Get-LrLogSources -Name $Id -Exact
            if ($LogSourceLookup.Error -eq $true) {
                return $LogSourceLookup
            } else {
                $Guid = $LogSourceLookup | Select-Object -ExpandProperty id
            }
        }

        $Body = Get-LrLogSourceDetails -Id $Id

        if ($Name) {
            $Body.name = $Name
        }

        if ($RecordStatus) {
            $Body.RecordStatus = $RecordStatus
        }

        if ($Status) {
            $Body.Status = $Status
        }

        if ($FilePath) {
            if ($null -eq $Body.filePath) {
                $Body | Add-Member -MemberType NoteProperty -Name 'filePath' -Value 'Bogus' -Force
            }
            $Body.filePath = $FilePath
        }

        if ($maxMsgCount) {
            $Body.maxMsgCount = $maxMsgCount
            $Body.msgPerCycle = $maxMsgCount
        }

        if ($MpePolicyId) {
            $MpePolicy = Get-LrMpePolicy -Id $MpePolicyId
            if (($null -ne $MpePolicy.Error) -and ($MpePolicy.Error -eq $true)) {
                return $MpePolicy
            } else {
                $Body.mpePolicy.id = $MpePolicy.id
                $Body.mpePolicy.name = $MpePolicy.name
            }
        }
        
        
        $RequestUrl = $BaseUrl + "/lr-admin-api/logsources/" + $Guid + "/"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"
        
        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $($Body | ConvertTo-Json) -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        if ($PassThru) {
            return $Response
        }
    }

    End { }
}