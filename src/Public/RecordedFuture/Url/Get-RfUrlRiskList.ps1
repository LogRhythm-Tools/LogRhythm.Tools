using namespace System
using namespace System.Collections.Generic

Function Get-RfUrlRiskList {
    <#
    .SYNOPSIS
        Get RecordedFuture URL threat list.
    .DESCRIPTION
        Get RecordedFuture URL cmdlet retrieves the associated threat list results with returned URL values and their associated data.  
    .PARAMETER Credential
        PSCredential containing an API Token in the Password field.
        
        Note: You can bypass the need to provide a Credential by setting
        the preference variable $LrtConfig.VirusTotal.VtApiToken
        with a valid Api Token.
    .PARAMETER List
        Name of the RecordedFuture URL ThreatList
    .PARAMETER Format
        Output format as provided by RecordedFuture.  This script currently only proceses 'csv/splunk' format.
        
        Possible formats:
        "csv/splunk", "xml/stix/1.1.1", "xml/stix/1.2"
    .PARAMETER Compressed
        Determines if the data should be compressed from RecordedFuture prior to sending to requestor.

        This script currently only supports non-compressed results.
    .PARAMETER MinimumRisk
        Sets the minimum risk value for returned object(s).  
    .PARAMETER MaximumRisk
        Sets the maximum risk value for returned object(s).
    .PARAMETER ValuesOnly
        Returns only the Name value of the associated list.

        This object is returned as an array to support passing arrays via pipeline as a parameter.
    .INPUTS
        String -> Token
        String -> List
        String -> Format
        Bool   -> Compressed
        Int    -> MinimumRisk
        Int    -> MaximumRisk
        Switch -> ValuesOnly
    .NOTES
        Recorded Future - API
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string] $List,


        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string] $Format = "csv/splunk",


        [Parameter(Mandatory = $false, Position = 2)]
        [bool] $Compressed = $false,


        [Parameter(Mandatory = $false, Position = 3)]
        [int] $MinimumRisk,


        [Parameter(Mandatory = $false, Position = 4)]
        [int] $MaximumRisk,


        [Parameter(Mandatory = $false, Position = 5)]
        [switch] $ValuesOnly,


        [Parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNull()]
        [pscredential] $Credential = $LrtConfig.RecordedFuture.ApiKey
    )

    Begin {
        $ResultsList = [list[psobject]]::new()
        $BaseUrl = $LrtConfig.RecordedFuture.BaseUrl
        $Token = $Credential.GetNetworkCredential().Password

        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("X-RFToken", $Token)

        Write-Verbose "$($Headers | Out-String)"

        # Request Setup
        $Method = $HttpMethod.Get

        # Check preference requirements for self-signed certificates and set enforcement for Tls1.2 
        Enable-TrustAllCertsPolicy
    }

    Process {
        # Establish General Error object Output
        $ErrorObject = [PSCustomObject]@{
            Error                 =   $false
            Value                 =   $List
            Code                  =   $Null
            Type                  =   $null
            Note                  =   $null
        }

        # Establish Query Parameters object
        $QueryParams = [Dictionary[string,string]]::new()

        # Format
        $QueryParams.Add("format", $Format)

        # Compression
        $QueryParams.Add("gzip", $Compressed)

        # List
        $QueryParams.Add("list", $List)


        if ($QueryParams.Count -gt 0) {
            $QueryString = $QueryParams | ConvertTo-QueryString
            Write-Verbose "[$Me]: QueryString is [$QueryString]"
        }



        # Define Search URL
        $RequestUrl = $BaseUrl + "/v2/url/risklist" + $QueryString
        Write-Verbose "[$Me]: Request URL: $RequestUrl"

        if ($Compressed -eq $false) {
            Try {
                $Results = Invoke-RestMethod $RequestUrl -Method $Method -Headers $Headers | ConvertFrom-Csv
            }
            catch {
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
        } else {
            Try {
                $Results = Invoke-WebRequest $RequestUrl -Method $Method -Headers $Headers
            }
            catch {
                $Err = Get-RestErrorMessage $_
                $ErrorObject.Error = $true
                $ErrorObject.Type = "System.Net.WebException"
                $ErrorObject.Code = $($Err.statusCode)
                $ErrorObject.Note = $($Err.message)
                return $ErrorObject
            }
            return $Results
        }


        # Set ResultsList - Parse CSV to Object Types
        $ResultsList = @($Results | Select-Object @{Name="Name";Expression={[string]$_.Name}},@{Name="Risk";Expression={[int32]$_.Risk}},@{Name="RiskString";Expression={[string]$_.RiskString}},@{Name="EvidenceDetails";Expression={[string]$_.EvidenceDetails}})

        # Filter returned results based on Risk score
        if ($MinimumRisk -and $MaximumRisk) {
            $ResultsList = $ResultsList.Where({([int32]$_.Risk -ge $MinimumRisk) -and ([int32]$_.Risk -le $MaximumRisk)})
        } elseif ($MinimumRisk) {
            $ResultsList = $ResultsList.Where({[int32]$_.Risk -ge $MinimumRisk})
        } elseif ($MaximumRisk) {
            $ResultsList = $ResultsList.Where({[int32]$_.Risk -le $MaximumRisk})
        }

        # Return Values only as an array or all results as object
        if ($ValuesOnly) {
            Return ,$ResultsList.Name
        } else {
            Return $ResultsList
        } 
    }
 

    End { }
}