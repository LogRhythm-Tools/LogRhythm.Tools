using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Get-LrMpeRules {
    <#
    .SYNOPSIS
        Retrieve a list of accepted MPE Rules from the LogRhythm.
    .DESCRIPTION
        Get-LrLogSources returns a list of accepted Log Sources, including details.
    .PARAMETER Id
        Filters results for a specific Log Source Type Id in resources.
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
    .PARAMETER PageCount
        Integer representing number of pages to return.  Default is maximum, 1000.
    .OUTPUTS
        PSCustomObject representing LogRhythm MPE Rules and their contents.
    .EXAMPLE
        PS C:\> Get-LrMpeRules
        ----
    .NOTES
        LogRhythm-API        
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [int32] $msgSourceTypeId,


        [Parameter(Mandatory = $false, Position = 1)]
        [int] $PageValuesCount = 1000,

        
        [Parameter(Mandatory = $false, Position = 2)]
        [int] $PageCount = 1,


        [Parameter(Mandatory = $false, Position = 3)]
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

        # Verify version
        if ($LrtConfig.LogRhythm.Version -match '7\.[0-8]\.\d+') {
            $ErrorObject.Error = $true
            $ErrorObject.Code = "404"
            $ErrorObject.Type = "Cmdlet not supported."
            $ErrorObject.Note = "This cmdlet is available in LogRhythm version 7.5.0 and greater."

            return $ErrorObject
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
        $Offset = ($PageCount -1) * $_pageValueCount
        $QueryParams.Add("offset", $Offset)

        # Filter by Object Name
        if ($msgSourceTypeId) {
            $_id = $msgSourceTypeId
            $QueryParams.Add("msgSourceTypeId", $_id)
        }

        # Build QueryString
        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }

        # Request URL
        $RequestUrl = $BaseUrl + "/lr-admin-api/mperules/" + $QueryString

        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        # Send Request
        $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }

        # Check if pagination is required, if so - paginate!
        if ($Response.data.Count -eq $PageValuesCount) {
            Write-Verbose "[$Me]: Begin Pagination"
            $MpeResults = [list[object]]::new()
            ForEach ($MpeData in $Response.data) {
                if ($MpeResults.mpeRuleId -notcontains $MpeData.mpeRuleId) {
                    $MpeResults.Add($MpeData)
                }
            }

            DO {
                # Increment Page Count / Offset
                $PageCount = $PageCount + 1
                $Offset = ($PageCount -1) * $PageValuesCount
                # Update Query Paramater
                $QueryParams.offset = $Offset
                # Apply to Query String
                $QueryString = $QueryParams | ConvertTo-QueryString
                # Update Query URL
                $RequestUrl = $BaseUrl + "/lr-admin-api/mperules/" + $QueryString
                Write-Verbose "[$Me]: Request URL: $RequestUrl"
                # Retrieve Query Results
                $PaginationResults = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Origin $Me
                if (($null -ne $PaginationResults.Error) -and ($PaginationResults.Error -eq $true)) {
                    return $PaginationResults
                }
                
                # Append results to Response
                ForEach ($MpeData in $PaginationResults.data) {
                    if ($MpeResults.mpeRuleId -notcontains $MpeData.mpeRuleId) {
                        $MpeResults.Add($MpeData)
                    }
                }
            } While ($($PaginationResults.data.Count) -eq $PageValuesCount)

            $Response = [PSCustomObject]@{
                alarmsSearchDetails = $MpeResults
                alarmsCount = $MpeResults.Count
                statusCode = $PaginationResults.statusCode
                statusMessage = $PaginationResults.statusMessage
                responseMessage = $PaginationResults.responseMessage
            }
            Write-Verbose "[$Me]: End Pagination"
        }

        return $Response
    }

    End {
    }
}