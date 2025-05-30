using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function Add-ExaContextRecords {
    <#
    .NOTES
        Exabeam-API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateNotNull()]
        [string] $ContextId,
        

        [Parameter(Mandatory = $true, Position = 1)]
        [PSCustomObject[]] $Data = @(),

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 2)]
        [ValidateSet(
            'append',
            'replace', 
            ignorecase=$true
        )]
        [string] $Operation,


        [Parameter(Mandatory = $false, Position = 3)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.Exabeam.ApiKey
    )
                                                                    
    Begin {
        $Me = $MyInvocation.MyCommand.Name
        Set-LrtExaToken
        # Request Setup
        $BaseUrl = $LrtConfig.Exabeam.BaseUrl
        $Token = $LrtConfig.Exabeam.Token.access_token


        # Define HTTP Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $Token")

        # Define HTTP Method
        $Method = $HttpMethod.Post
        
        # Define HTTP URI
        $RequestUrl = $BaseUrl + "context-management/v1/tables/$ContextId/addRecords"

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2
        Enable-TrustAllCertsPolicy

        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Data                  =   $Data
            Note                  =   $null
            Value                 =   $null
        }
    }

    Process {
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        $SegmentCount = ([Math]::Round(($($Data.Count) / 20000), 0)) +1
        $SegmentedAddList = Create-LrPsArraySegments -InputArray $Data -Segments $SegmentCount
        $Segment = 0
        foreach ($AddArray in $SegmentedAddList) {
            $Segment += 1
            Write-Verbose "[$Me]: $(Get-TimeStamp) - Submitting $($AddArray.count) - Segment: $Segment/$SegmentCount"
            Try {
                # Build the JSON Body
                $Body = @{
                    operation   = $Operation
                    data        = $AddArray
                } | ConvertTo-Json -Depth 5 -Compress

                # Send Request
                $Response = Invoke-RestAPIMethod -Uri $RequestUrl -Headers $Headers -Method $Method -Body $Body -Origin $Me
            } Catch {
                $ErrorObject.Error = $true
                $ErrorObject.Note = "Failed to submit addition entries."
                $ErrorObject.Value = $AddArray
            }
        }

        if (($null -ne $Response.Error) -and ($Response.Error -eq $true)) {
            return $Response
        }
        
        return $Response
    }

    End { }
}
