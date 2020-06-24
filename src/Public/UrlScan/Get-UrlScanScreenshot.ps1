using namespace System
using namespace System.Collections.Generic

Function Get-UrlScanScreenshot {
    <#
    .SYNOPSIS
        Get a URL Screenshot from a UrlScan.io scan
    .DESCRIPTION
        Returns a screenshot for a URL based on the UrlScan service.   
    .PARAMETER Uuid
        Uuid - universally unique identifier
    .PARAMETER Path
        
    .INPUTS
        System.String -> Uuid
        -> Path
    .OUTPUTS
        PNG image saved to the destination path.
    .EXAMPLE
        PS C:\> Get-UrlScanResults -Credential $token -Uuid "5b0802d3-803e-4f76-9b41-698d2fb3fa13
        ---
    .NOTES
        UrlScan-API    
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string] $Uuid,

        [Parameter(Mandatory = $false, Position = 1)]
        [string] $Path,

        [Parameter(Mandatory = $false, Position = 2)]
        [string] $FileName

    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name
        $BaseUrl = $LrtConfig.UrlScan.ScreenshotUrl

        $Method = $HttpMethod.Get
    }

    Process {
        # Request URI   

        $RequestUrl = $BaseUrl + $Uuid + ".png"
        Write-Verbose "[$Me]: RequestUrl: $RequestUrl"

        if (!$Path) {
            $Path = "./"
        }

        if (!$Filename) {
            $FileName = "$Uuid.png"
        }

        if (!(Test-Path -Path $Path)) {
            New-Item -Path $Path -ItemType directory
        }
        $FullPath = "$Path$FileName"



        Try {
            $Response = Invoke-WebRequest $RequestUrl -Method $Method -OutFile $FullPath
        }
        catch [System.Net.WebException] {
            $Err = Get-RestErrorMessage $_
            throw [Exception] "[$Me] [$($Err.statusCode)]: $($Err.message) $($Err.details)`n$($Err.validationErrors)`n"
        }

        Return $Response
    }


    End { }
} 