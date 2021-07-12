using namespace System
using namespace System.IO
using namespace System.Collections.Generic

Function New-LrtAzMailMessage {
    <#
    .SYNOPSIS
        Send a mail message through Azure.
    .DESCRIPTION

    .PARAMETER Token
        An access token issued by the Microsoft identity platform with a valid claim to Microsoft
        Graph. The registered application will require the IdentityRiskyUser.Read.All role.
    .PARAMETER Top
        The Top parameter sets the page size of results.
    .INPUTS
        None
    .OUTPUTS
        A collection of signIn objects designed as being "At Risk" by the Identity platform.
        https://docs.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta#properties
    .EXAMPLE
        PS C:\> 
    .NOTES
        Azure-API
    .LINK
        https://github.com/GeneCupstid/SRF-Private
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, Position = 0)]
        [string] $SenderPrincipalName,


        [Parameter(Mandatory = $false, Position = 1)]
        [string[]] $Recipients,


        [Parameter(Mandatory = $false, Position = 2)]
        [string] $Subject,


        [Parameter(Mandatory = $false, Position = 3)]
        [string] $Body,


        [Parameter(Mandatory = $false, Position = 4)]
        [ValidateSet('text','html', ignorecase=$true)]
        [string] $BodyType
    )

    Begin {
        $Me = $MyInvocation.MyCommand.Name

        $AccessToken = Get-LrtAzToken -ResourceName AzureAd | Select-Object -ExpandProperty access_token
        

        # Enable self-signed certificates and Tls1.2
        Enable-TrustAllCertsPolicy
    }


    Process {
        # Request Headers
        $Headers = [Dictionary[string,string]]::new()
        $Headers.Add("Authorization", "Bearer $AccessToken")
        $Headers.Add("Content-type", "application/json")


        # Request URI
        # https://docs.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0&tabs=http
        $Method = $HttpMethod.Post
        $RequestUri = "https://graph.microsoft.com/v1.0/users/$SenderPrincipalName/sendMail"

        # https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messages?$filter=ReceivedDateTime ge 2017-04-01 and receivedDateTime lt 2017-05-01

        $RecipientObjects = [list[object]]::new()
        ForEach ($Recipient in $Recipients) {
            $RecipientObject = [PSCustomObject]@{
                emailAddress = [PSCustomObject]@{
                    address = $Recipient
                }
            }
            if ($RecipientObjects -notcontains $RecipientObject) {
                $RecipientObjects.Add($RecipientObject)
            }
        }

        # MessageBody
        $Body = [PSCustomObject]@{
            message = [PSCustomObject]@{
                subject = $Subject
                body = [PSCustomObject]@{
                    contentType = $BodyType
                    content = $Body
                }
                toRecipients = @($RecipientObjects)
            }
        } | ConvertTo-Json -Depth 4

        Write-Verbose "Body:`r`n$Body"

        # REQUEST
        try {
            $Response = Invoke-RestMethod `
                -Uri $RequestUri `
                -Headers $Headers `
                -Method $Method `
                -Body $Body
        } catch [System.Net.WebException] {
            return $_
            throw [Exception] "[$Me] [$($Err.error.code)]: $($Err.error.message)`n"
        }

    

        return $Response
    }

    End { }
}