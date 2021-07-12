using namespace System.Collections.Generic
<#
    .SYNOPSIS
        Expands URLs from the following providers:
           Bitly
           Twitter
           GoDaddy
           Tiny.cc
           Google
           TinyUrl
           Rebrandly
    .OUTPUTS
        PSCustomObject containing the Shortlink status, Shortlink provider, before URL, after URL.
    .EXAMPLE
        Invoke-PIEUrlExpand -Url 'https://bit.ly/37lYpxb'
        ---
        Status Provider Before                 After
        ------ -------- ------                 -----
        True   Bitly    https://bit.ly/37lYpxb https://github.com/Jt3kt/PIE
    .NOTES
        PIE      
    .LINK
        https://github.com/LogRhythm-Tools/LogRhythm.Tools
#>
function Invoke-PIEUrlExpand {
    [CmdLetBinding()]
    param( 
        [Parameter(Mandatory = $false, Position = 0)]
        [ValidateNotNull()]
        [System.Uri]$Url
    )

    Begin {
        # Define URL Shortlink Services
        $URLShortlinkServices = [list[object]]::new()
        $URLShortlinkServices.Add(@{Name="Bitly";Regex=@('^.*bit\.ly/.*')})
        $URLShortlinkServices.Add(@{Name="Twitter";Regex=@('^.*t\.co/.*')})
        $URLShortlinkServices.Add(@{Name="GoDaddy";Regex=@('^.*x\.co/.*')})
        $URLShortlinkServices.Add(@{Name="Tiny.cc";Regex=@('^.*tiny\.cc/.*')})
        $URLShortlinkServices.Add(@{Name="Google";Regex=@('^.*goo\.gl/.*')})
        $URLShortlinkServices.Add(@{Name="TinyUrl";Regex=@('^.*tinyurl\.com/.*')})
        $URLShortlinkServices.Add(@{Name="Rebrandly";Regex=@('^.*rb\.gy/.*')})

        $RedirectCodes = @(301, 302, 303, 308)
    }

    Process {
        # Object that represents the data points for URL Shortlink services
        $Shortlink = [PSCustomObject]@{
            Status = $False
            Provider = $null
            Before = $Url
            After = $null
        }

        # Check for Shortened URL
        ForEach ($URLShortlinkService in $URLShortlinkServices) {
            ForEach ($RegexPattern in $URLShortlinkService.Regex) {
                $URLShortlinkStatus = $Shortlink.Before -Match $RegexPattern
                if ($URLShortlinkStatus -eq $true) {
                    break
                }
            }
            if ($URLShortlinkStatus -eq $true) {
                $ShortLink.Status = $URLShortlinkStatus
                $ShortLink.Provider = $URLShortlinkService.Name
                break
            }
        }

        if ($Shortlink.Status -eq $True) {
            $ShortLinkCnt = 0
            $TempURL = $Shortlink.Before
            Do {
                Write-Verbose $TempURL
                $Results = Invoke-WebRequest -Method Head -Uri $TempURL -MaximumRedirection 0 -ErrorAction SilentlyContinue
                if ($RedirectCodes -Contains $Results.StatusCode) {
                    $TempURL = $Results.Headers.Location
                }
                $ShortLinkCnt += 1
                Write-Verbose $($Results.StatusCode)
            } while (($Results.Headers.Location) -and ($ShortLinkCnt -lt 15))

            $Shortlink.After = $TempURL
        }
        

        Return $Shortlink
    }
}