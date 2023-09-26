using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-LrLogSource {
    <#
    .SYNOPSIS
        Add the Log Source to an existing System Monitor Agent host.
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
     
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNull()]
        [int32] $SystemMonitorId,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [ValidateNotNull()]
        [int32] $HostId,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 2)]
        [ValidateNotNull()]
        [int32] $EntityId,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateNotNull()]
        [int32] $LogSourceTypeId,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 4)]
        [ValidateNotNull()]
        [int32] $MpePolicyId,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 5)]
        [ValidateSet('NoRulesProcessing','EventForwardingEnabled', 'EventForwardingEnabled', ignorecase=$true)]
        [string] $MpeProcessingMode,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 6)]
        [string] $Name,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 7)]
        [ValidateSet('Active','Retired', ignorecase=$true)]
        [string] $RecordStatus,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 8)]
        [ValidateSet('Enabled','Disabled', 'Unregistered', ignorecase=$true)]
        [string] $Status,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 9)]
        [string] $FilePath,


        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 10)]
        [ValidateRange(1, 10000)]
        [int32] $maxMsgCount,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 11)]
        [string] $ShortDescription,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 12)]
        [string] $LongDescription,

        [Parameter(Mandatory = $false, Position = 13)]
        [switch] $PassThru,

        [Parameter(Mandatory = $false, Position = 14)]
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
        $Method = $HttpMethod.Post
        

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

        $AgentInfo = Get-LrAgentDetails -Id $SystemMonitorId
        if (($null -ne $AgentInfo.Error) -and ($AgentInfo.Error -eq $true)) {
            return $AgentInfo
        }

        $HostInfo = Get-LrHostDetails -Id $HostId
        if (($null -ne $HostInfo.Error) -and ($HostInfo.Error -eq $true)) {
            return $HostInfo
        }

        if ($EntityId) {
            $EntityInfo = Get-LrEntityDetails -Id $EntityId
            if (($null -ne $EntityInfo.Error) -and ($EntityInfo.Error -eq $true)) {
                return $EntityInfo
            }
        } else {
            $EntityInfo = $HostInfo.entity
        }

        $LogTypeInfo = Get-LrLogSourceTypeDetails -Id $LogSourceTypeId
        if (($null -ne $LogTypeInfo.Error) -and ($LogTypeInfo.Error -eq $true)) {
            return $LogTypeInfo
        }

        $MpeInfo = Get-LrMpePolicy -Id $MpePolicyId
        if (($null -ne $MpeInfo.Error) -and ($MpeInfo.Error -eq $true)) {
            return $MpeInfo
        }

        if ($ShortDescription) {
            $_shortDescription = $ShortDescription
        } else {
            $_shortDescription = ""
        }

        if ($LongDescription) {
            $_longDescription = $LongDescription
        } else {
            $_longDescription = ""
        }

        $Body = [PSCustomObject]@{
            id = -1
            systemMonitorId = $AgentInfo.id
            systemMonitorName = $AgentInfo.name
            name = $Name
            host = [PSCustomObject]@{
              id = $HostInfo.id
              name = $HostInfo.name
            }
            entity = [PSCustomObject]@{
              id = $EntityInfo.id
              name = $EntityInfo.name
            }
            logSourceType = [PSCustomObject]@{
              id = $LogTypeInfo.id
              name = $LogTypeInfo.name
            }
            mpePolicy = [PSCustomObject]@{
              id = $MpeInfo.id
              name = $MpeInfo.name
            }
            shortDescription = $_shortDescription
            longDescription = $_longDescription
            recordStatus = $RecordStatus
            status = $Status
            isVirtual = $false
            logMartMode = 0
            isLoadBalanced = $false
            mpeProcessingMode = $MpeProcessingMode
            isArchivingEnabled = $true
            maxMsgCount = $maxMsgCount
            defMsgTTLValue = 0
#            dateUpdated = "2023-09-21T14:14:10Z"
            isSilentLogSourceEnabled = $false
            msgSourceDateFormatID = 0
            filePath = $FilePath
            cryptoMode = 0
            signMode = 0
#            monitorStart = "2023-09-21T14:14:10Z"
#            monitorStop = "2023-09-21T14:14:10Z"
            defMsgTTL = 0
            msgPerCycle = $maxMsgCount
            collectionDepth = 0
#            udlaConnectionString = "string"
#            udlaStateField = "string"
#            udlaStateFieldType = "Increment"
#            udlaStateFieldConversion = "string"
#            udlaQueryStatement = "string"
#            udlaOutputFormat = "string"
#            udlaUniqueIdentifier = "string"
#            udlaMsgDateField = "string"
#            udlaGetUTCDateStatement = "string"
            parameter1 = 0
            parameter2 = 0
            parameter3 = 0
            parameter4 = 0
#            parameter5 = 0
#            parameter6 = "string"
#            parameter7 = "string"
#            parameter8 = "string"
#            parameter9 = "string"
#            parameter10 = "string"
#            msgRegexStart = "string"
#            msgRegexDelimeter = "string"
#            msgRegexEnd = "string"
#            recursionDepth = 0
            isDirectory = $false
#            inclusions = "string"
#            exclusions = "string"
            compressionType = "none"
#            udlaConnectionType = 0
            collectionThreadTimeout = 120
#            virtualSourceRegex = "string"
#            virtualSourceSortOrder = 0
#            virtualSourceCatchAllID = 0
            persistentConnection = $false
            autoAcceptanceRuleId = "Manual"
#            maxLogDate = "2023-09-21T14:14:10Z"
#            virtualLogSourceParentID = 0
#            virtualLogSourceName = "string"
            watchFileRenameOnRollover = $true
          }
 
        
        $RequestUrl = $BaseUrl + "/lr-admin-api/logsources/"
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