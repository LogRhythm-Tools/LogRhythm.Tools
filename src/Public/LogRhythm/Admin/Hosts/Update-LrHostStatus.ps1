using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Update-LrHostStatus {
    <#
    .SYNOPSIS
        Enables bulk update for Host status within the LogRhythm Entity structure.
    .DESCRIPTION
        Update-LrHostStatus allows you to set a LogRhythm Host record as Active or Retired.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER HostId
        Integer value(s) for assciated Host ID or Name.

        When presented with a non-iteger value an exact lookup is performed to identify the HostID integer value.
    .PARAMETER Status
        String value for the desired stats.

        Valid input: "Retired" "Active"
    .OUTPUTS
        Successful completion of this cmdlet currently returns no output.  Verify results with Get-LrHosts
    .EXAMPLE
        PS C:\> Update-LrHostStatus -HostId "" -Status "Retired"
        ----
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

        [Parameter(Mandatory = $false, Position = 1)]
        [string[]]$HostId,

        [Parameter(Mandatory = $false, Position = 2)]
        [string]$Status
    )

    Begin {
        # Request Setup
        $BaseUrl = $LrtConfig.LogRhythm.AdminBaseUrl
        $Token = $Credential.GetNetworkCredential().Password
        
        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Put

        # Define LogRhythm Version
        $LrVersion = $LrtConfig.LogRhythm.Version

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Integer Reference
        $_int = 0
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $HostId
            Note                  =   $null
        }

        # Status
        if ($Status) {
            $ValidStatus = "active", "retired"
            if ($ValidStatus.Contains($($Status.ToLower()))) {
                $_status = (Get-Culture).TextInfo.ToTitleCase($Status)
            } else {
                throw [ArgumentException] "Status [$StatusStatus] must be: active, or retired."
            }
        }

        $HostIDs = [list[Object]]::new()

        # Check if ID value is an integer
        ForEach ($Id in $HostId) {
            if ([int]::TryParse($Id, [ref]$_int)) {
                Write-Verbose "[$Me]: Id parses as integer."
                $_id = Get-LrHostDetails -Id $Id
                if ($_id.Error) {

                } else {
                    [int32]$Guid = $Id
                    $HostRecord = [PSCustomObject]@{
                        hostId = $Guid
                        status = $_status
                    }
                    $HostIDs.Add($HostRecord)
                }
            } else {
                Write-Verbose "[$Me]: Id does not parse as integer.  Performing string lookup."
                $_id = Get-LrHosts -Name $HostId -Exact
                if (!$Guid) {

                } else {
                    [int32]$Guid = $_id | Select-Object -ExpandProperty id 
                    $HostRecord = [PSCustomObject]@{
                        hostId = $Guid
                        status = $_status
                    }
                    $HostIDs.Add($HostRecord)
                }
            }
        }

        # Request Body
        $Body = @( $HostIDs )

        $Body = ConvertTo-Json -InputObject $Body

        Write-Verbose $Body

        # Request URL
        $RequestUrl = $BaseUrl + "/hosts/status/"

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

        Return $Response
    }

    End { }
}