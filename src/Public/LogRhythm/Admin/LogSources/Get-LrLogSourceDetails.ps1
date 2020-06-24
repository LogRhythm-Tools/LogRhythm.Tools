using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrLogSourceDetails {
    <#
    .SYNOPSIS
        Retrieve the Log Source Details from the LogRhythm.
    .DESCRIPTION

    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        [System.String] (Name or Int)
        Specifies a LogRhythm host object by providing one of the following property values:
          + List Name (as System.String), e.g. "MYSECRETHOST"
          + List Int (as System.Int), e.g. 2657

        Can be passed as ValueFromPipeline but does not support Arrays.
    .OUTPUTS
        PSCustomObject representing LogRhythm Entity Network record and its contents.
    .EXAMPLE
        PS C:\> Get-LrLogSourceDetails -Id 2
        ----
        id                       : 2
        systemMonitorId          : 1
        name                     : XM WinEvtXML - Sys
        host                     : @{id=1; name=SupportXM747}
        entity                   : @{id=1; name=Primary Site}
        logSourceType            : @{id=1000662; name=MS Windows Event Logging XML - System}
        mpePolicy                : @{id=-1000662; name=LogRhythm Default}
        trueSourcePolicy         :
        recordStatus             : Active
        status                   : Enabled
        isVirtual                : False
        logMartMode              : 13627389
        isLoadBalanced           : False
        mpeProcessingMode        : EventForwardingEnabled
        isArchivingEnabled       : True
        maxMsgCount              : 0
        defMsgTTLValue           : 0
        dateUpdated              : 2019-07-17T22:49:07.62Z
        isSilentLogSourceEnabled : False
        filePath                 : SupportXM747:System
        cryptoMode               : 0
        signMode                 : 0
        defMsgTTL                : 0
        defMsgArchiveMode        : Override_Archive
        msgPerCycle              : 100
        collectionDepth          : 0
        udlaStateFieldType       : Increment
        parameter1               : 0
        parameter2               : 0
        parameter3               : 0
        parameter4               : 0
        recursionDepth           : 0
        isDirectory              : False
        compressionType          : none
        udlaConnectionType       : 0
        collectionThreadTimeout  : 120
        virtualSourceSortOrder   : 0
        virtualSourceCatchAllID  : 0
        persistentConnection     : False
        autoAcceptanceRuleId     :
        maxLogDate               : 2019-07-18T15:13:26.3Z

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

        [Parameter(Mandatory = $true, ValueFromPipeline=$true, Position = 1)]
        [ValidateNotNull()]
        [object] $Id
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Get

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
        }

        # Check if ID value is an integer
        if ([int]::TryParse($Id, [ref]$_int)) {
            Write-Verbose "[$Me]: Id parses as integer."
            $Guid = $Id
        } else {
            Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
            $LogSourceLookup = Get-LrLogSources -Name $Id -Exact
            if ($NetworkLookup.Error -eq $true) {
                $ErrorObject.Error = $LogSourceLookup.Error
                $ErrorObject.Type = $LogSourceLookup.Type
                $ErrorObject.Code = $LogSourceLookup.Code
                $ErrorObject.Note = $LogSourceLookup.Note
                return $ErrorObject
            } else {
                $Guid = $LogSourceLookup | Select-Object -ExpandProperty id
            }
        }

        
        $RequestUrl = $BaseUrl + "/logsources/" + $Guid + "/"
        # Error Output - Used to support Pipeline Paramater ID
        Write-Verbose "[$Me]: Id: $Id - Guid: $Guid - ErrorStatus: $($ErrorObject.Error)"
        if ($ErrorObject.Error -eq $false) {
            # Send Request
            if ($PSEdition -eq 'Core'){
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method -SkipCertificateCheck
                }
                catch [System.Net.WebException] {
                    $Err = Get-RestErrorMessage $_
                    $ErrorObject.Error = $true
                    $ErrorObject.Type = "System.Net.WebException"
                    $ErrorObject.Code = $($Err.statusCode)
                    $ErrorObject.Note = $($Err.message)
                    return $ErrorObject
                }
            } else {
                try {
                    $Response = Invoke-RestMethod $RequestUrl -Headers $Headers -Method $Method
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
        } else {
            return $ErrorObject
        }

        return $Response
    }

    End { }
}