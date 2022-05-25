function Invoke-RestAPIMethod {
    [CmdletBinding()]
    Param(
        [Parameter(Position=0, Mandatory=$true)]
        [string]$Uri,

        [Parameter(Position=1, Mandatory=$true)]
        [string]$Method,

        [Parameter(Position=2, Mandatory=$false)]
        [Dictionary[string,string]]$Headers,

        [Parameter(Position=3, Mandatory=$false)]
        [string]$Body,

        [Parameter(Position=4, Mandatory=$false)]
        [string]$ContentType = 'application/json',

        [Parameter(Position=5, Mandatory=$false)]
        [int]$MaxRetries = 25,

        [Parameter(Position=6, Mandatory=$false)]
        [int]$Delay = 500,

        [Parameter(Position=7, Mandatory=$false)]
        [string]$Origin
    )
    Begin {
        $RetryCounter = 0
     }

    Process {
        $ErrorObject = [PSCustomObject]@{
            Request               =   $null
            Reason                =   $null
            Code                  =   $null
            Error                 =   $false
            Type                  =   $null
            Note                  =   $null
            Origin                =   $Origin
            Raw                   =   $null
        }
        Do {
            $RetryRequest = $false
            Try {
                if ($Body) {
                    $Response = Invoke-RestMethod -Method $Method -Uri $Uri -Body $Body -Headers $Headers -ContentType $ContentType
                } else {
                    $Response = Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ContentType $ContentType
                }
            } Catch {
                if($_.Exception.Response.StatusCode.value__ -eq 429 ){
                    if($RetryCounter -ge $MaxRetries){
                        $RetryRequest = $false
                    } else {
                        $RetryCounter += 1
                        $RetryRequest = $true
                        Start-Sleep -Milliseconds $Delay
                    }
                } else {
                    $ErrorObject.Error = $true
                    $ErrorObject.Request = $_.CategoryInfo.Activity
                    $ErrorObject.Reason = $_.CategoryInfo.Reason
                    $ErrorObject.Code = $_.Exception.Response.StatusCode.value__
                    switch ($_.Exception.Response.StatusCode.value__){
                        400 {$ErrorObject.Note = "Bad request.  Validate request data and/or API services."}
                        401 {$ErrorObject.Note = "Unauthorized to access resource.  Validate API Key."}
                        403 {$ErrorObject.Note = "Access Forbidden.  Validate API Key."}
                        404 {$ErrorObject.Note = "Resource not found or you do not have permission to view it."}
                        405 {$ErrorObject.Note = "Method Not Allowed.  Validate request data."}
                        408 {$ErrorObject.Note = "Connection timeout.  Validate API access from execution source."}
                        default {
                            $ErrorObject.Note = $_.ErrorDetails.Message
                        }
                    }

                    $ErrorObject.Type = $_.Exception.Response.StatusCode
                    $ErrorObject.Raw = $_
                    return $ErrorObject
                }
            }
        } While ($RetryRequest)

        return $Response
    }
}