using namespace System
using namespace System.Collections.Generic

function Get-RfSoarEnrichment {
    <#
        .SYNOPSIS
            Get-RfSoarEnrichment calls the RecordedFuture SOAR Enrichment API to get additional information about IoCs (called Entities by RF)

        .DESCRIPTION
            Get RecordedFuture SOAR Enrichment makes a call to bulk retrieve information about a list of IoCs

        .PARAMETER Credential
            PSCredential containing an API Token in the Password field.
            
            Note: You can bypass the need to provide a Credential by setting
            the preference variable $LrtConfig.RecordedFuture.RfApiToken
            with a valid Api Token.

        .PARAMETER IoCList
            PSCustomObject containing arrays of IoCs for which to get enrichment data
            $IoCList = [PSCustomObject]@{
                ip = @{$IpList}
                domain = @{$DomainList}
                vulnerability = @{$cveList}
                hash = @{$HashList}
                url = @{$UrlList}
            }
            Any one or more of the IoC Types can be specified, each may have one or more entries.

        .EXAMPLE
            $IoCList = [PSCustomObject]@{
                ip = {'1.1.188.10'}
            }
            PS C:\> Get-RfSoarEnrichment -IoCList $IoCList
            ---
            risk        : {score: 89}
            ...

    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [PsCustomObject] $IoCList,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.RecordedFuture.ApiKey
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $BaseUrl = $LrtConfig.RecordedFuture.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("X-RFToken", "$Token")
        
        $Method = $HttpMethod.post
    }

    Process {
        # Request URI   
        $RequestUrl = $BaseUrl + "/v2//soar/enrichment?metadata=false"

        $Body = $IoCList | ConvertTo-Json -Depth 5 -Compress
        Write-Verbose "[$Me]: Request URL: $RequestUrl"
        Write-Verbose "[$Me]: Request Body:`n$Body"

        Try {
            $rfResponse = Invoke-RestMethod -Uri $RequestUrl -Method $Method -Headers $Headers -Body $Body -ContentType "application/json"
        }
        catch {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }

        Return $rfResponse
    }
 

    End {}

}