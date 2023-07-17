using namespace System
using namespace System.Collections.Generic

Function Update-RfAlert {
    <#
    .SYNOPSIS
        Update RecordedFuture Alert details for a specified alert.
    .DESCRIPTION
        Update RecordedFuture Alert allows for updating the details for a specific alert.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER Id
        Id value for Recorded Future Alert retrieval.
    .INPUTS

    .NOTES
        RecordedFuture-API v2
    .LINK
        https://api.recordedfuture.com/v2/#!/Alerts/Alert_Notification_Update
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $AlertId,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('unassigned','assigned', 'pending', 'dismiss', 'no-action', 'actionable', 'tuning', ignorecase=$true)]
        [string] $Status,


        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Note,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.RecordedFuture.ApiKey
    )

    Begin {
        $BaseUrl = $LrtConfig.RecordedFuture.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("X-RFToken", $Token)
        $Headers.Add("Content-Type", "application/json")

        Write-Verbose "$($Headers | Out-String)"

        # Request Setup
        $Method = $HttpMethod.Post

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {

        # Define Search URL
        $RequestUrl = $BaseUrl + "/v2/alert/update"
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Establish JSON Body contents
        $BodyContents = [PSCustomObject]@{
            id = $AlertId
        }

        if ($Status) {
            $BodyContents | Add-Member -MemberType NoteProperty -Name 'status' -Value $Status
        }

        if ($Note) {
            $BodyContents | Add-Member -MemberType NoteProperty -Name 'note' -Value $Note
        }



        # Establish Body Contents
        $Body = '[' + $(@($BodyContents) | ConvertTo-Json) + ']'
        Write-Verbose "[$Me]: Request Body:`n$Body"

        Try {
            $Results = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers -Body $Body
        } catch {
            If ($_.Exception.Response.StatusCode.value__) {
                $HTTPCode = ($_.Exception.Response.StatusCode.value__ ).ToString().Trim()
                Write-Verbose "HTTP Code: $HTTPCode"
            }
            If  ($_.Exception.Message) {
                $ExceptionMessage = ($_.Exception.Message).ToString().Trim()
                Write-Verbose "Exception Message: $ExceptionMessage"
                return $ExceptionMessage
            }
        }

        
        # Return Values only as an array or all results as object
        Return $Results.data
    }

    End { }
}