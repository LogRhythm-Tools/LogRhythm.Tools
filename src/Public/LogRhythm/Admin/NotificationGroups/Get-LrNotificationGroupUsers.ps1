using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrNotificationGroupUsers {
    <#
    .SYNOPSIS
        Retrieve a list of users assigned to a specific Notification Group.
    .DESCRIPTION
        Get-LrNotificationGroupUsers returns a full listing LogRhythm Notification Group user records, including details and content items.
    .PARAMETER Name
        Filter to return contents for Notification Groups where the name explicitly matches the name of an existing Notification Group record.

        This field supports submission of ID # in substitution of Name values.
    .PARAMETER RecordStatus,

    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .INPUTS

    .OUTPUTS

    .EXAMPLE
 
    .EXAMPLE
        Get-LrNotificationGroupUsers -Name "TAM Team"

        firstName         : Cu
        middleName        : 
        lastName          : Ta
        userType          : Individual
        fullName          : Ta, Cu
        objectPermissions : @{readAccess=Private; writeAccess=Private; entity=; owner=}
        id                : 9
        recordStatusName  : Active
        dateUpdated       : 5/10/2021 1:20:13 PM

        firstName         : Eric
        middleName        : 
        lastName          : Hart
        userType          : Individual
        fullName          : Hart, Eric
        objectPermissions : @{readAccess=PublicGlobalAdmin; writeAccess=PublicGlobalAdmin; entity=; owner=}
        id                : 6
        recordStatusName  : Active
        dateUpdated       : 5/10/2021 1:20:13 PM

        firstName         : Ho
        middleName        : 
        lastName          : Gu
        userType          : Individual
        fullName          : Gu, Ho
        objectPermissions : @{readAccess=PublicGlobalAdmin; writeAccess=PublicGlobalAdmin; entity=; owner=}
        id                : 8
        recordStatusName  : Active
        dateUpdated       : 5/10/2021 1:20:13 PM
    .EXAMPLE
        Get-LrNotificationGroupUsers -Name "TAM Tea"

        Error : True
        Type  : Record not found or permissions restricting access
        Code  : 404
        Note  : Unable to locate Notification Group based on provided Notification Group.
        Raw   : TAM Tea
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $Name,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [int[]] $id,


        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 3)]
        [ValidateSet('all','active', 'retired', ignorecase=$true)]
        [string] $RecordStatus = 'active',

        
        [Parameter(Mandatory = $false, Position = 4)]
        [switch] $Exact,


        [Parameter(Mandatory = $false, Position = 5)]
        [int] $PageValuesCount = 1000,


        [Parameter(Mandatory = $false, Position = 6)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 7)]
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
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy

        # Integer Reference
        [int32]$_int = 1
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Type                  =   $null
            Code                  =   $null
            Note                  =   $null
            Raw                   =   $null
        }

        #region: Process Query Parameters____________________________________________________
        $QueryParams = [Dictionary[string,string]]::new()

        # PageCount
        if ($PageValuesCount) {
            $_pageValueCount = $PageValuesCount
        } else {
            $_pageValueCount = 1000
        }
        # PageValuesCount - Amount of Values per Page
        $QueryParams.Add("count", $_pageValueCount)

        # Query Offset - PageCount
        $Offset = $PageCount - 1
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if (!$Id -and $Name) {
            if ([int]::TryParse($Name, [ref]$_int)) {
                Write-Verbose "[$Me]: Name parses as integer."
                $NotificationResults = Get-LrNotificationGroups -Id $Name
            } else {
                $NotificationResults = Get-LrNotificationGroups -Name $Name -Exact
            }

            if ($NotificationResults) {
                $_id = $NotificationResults.id
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Code = 404
                $ErrorObject.Type = "Record not found or permissions restricting access"
                $ErrorObject.Raw = $Name
                $ErrorObject.Note = "Unable to locate Notification Group based on provided Notification Group."
                return $ErrorObject
            }
        } elseif ($Id) {
            $NotificationResults = Get-LrNotificationGroups -Id $Id

            if ($NotificationResults) {
                $_id = $NotificationResults.id
            } else {
                $ErrorObject.Error = $true
                $ErrorObject.Code = 404
                $ErrorObject.Type = "Record not found or permissions restricting access"
                $ErrorObject.Raw = $Id
                $ErrorObject.Note = "Unable to locate Notification Group based on provided Notification Group ID #."
                return $ErrorObject
            }
        } else {
            $ErrorObject.Error = $true
            $ErrorObject.Code = 404
            $ErrorObject.Type = "User Input Error"
            $ErrorObject.Note = "Cmdlet requires Name or ID paramater values.  Please re-submit with name or ID value provided."
            return $ErrorObject
        }


        # RecordStatus
        if ($RecordStatus) {
            $_recordStatus = $RecordStatus.ToLower()
            $QueryParams.Add("recordStatus", $_recordStatus)
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/notification-groups/$_id/users/" + $QueryString

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Check if pagination is required, if so - paginate!
        if ($Response.Count -eq $PageValuesCount) {
            DO {
                # Increment Page Count / Offset
                #$PageCount = $PageCount + 1
                $Offset = $Offset + 1
                # Update Query Paramater
                $QueryParams.offset = $Offset
                # Apply to Query String
                $QueryString = $QueryParams | ConvertTo-QueryString
                # Update Query URL
                $RequestUrl = $BaseUrl + "/lr-admin-api/notification-groups/$_id/users/" + $QueryString

                Write-Verbose "[$Me]: Request URL: $RequestUrl"

                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if ($PaginationResults.Error) {
                    return $PaginationResults
                }
                
                # Append results to Response
                $Response = $Response + $PaginationResults
            } While ($($PaginationResults.Count) -eq $PageValuesCount)
            $Response = $Response | Sort-Object -Property Id -Unique
        }

        return $Response
    }

    End { }
}